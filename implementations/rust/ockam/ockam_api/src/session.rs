use core::fmt;
use core::future::Future;
use core::pin::Pin;
use crate::nodes::registry::SecureChannelInfo;
use crate::nodes::service::map_multiaddr_err;
use minicbor::{Encode, Decode};
use ockam::{Worker, TransportMessage, LocalMessage};
use ockam_core::{LOCAL, Address, Error, Route, Routed, Encodable, Decodable};
use ockam_core::errcode::{Kind, Origin};
use ockam_core::compat::rand;
use ockam_core::compat::collections::HashMap;
use ockam_core::compat::sync::Arc;
use ockam_multiaddr::{MultiAddr, proto};
use ockam_node::Context;
use ockam_node::tokio;
use ockam_node::tokio::task::JoinHandle;
use ockam_node::tokio::time::{self, Duration};
use ockam_node::tokio::sync::mpsc;
use ockam_node::tokio::sync::Mutex;
use petgraph::stable_graph::StableDiGraph;
use petgraph::graph::NodeIndex;
use petgraph::Direction;
use tinyvec::ArrayVec;
use tracing as log;

const MAX_FAILURES: usize = 3;

type Restart = Pin<Box<dyn Future<Output = Result<Address, Error>> + Send>>;

struct Node {
    worker: Address,
    status: Status,
    restarter: Option<Box<dyn FnMut() -> Restart + Send>>
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("worker", &self.worker)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Debug)]
enum Status {
    Down,
    Starting(JoinHandle<Result<Address, Error>>),
    Up
}

impl Status {
    fn is_up(&self) -> bool {
        matches!(self, Status::Up)
    }
}

#[derive(Debug, Copy, Clone)]
struct Ref(NodeIndex);

#[derive(Debug)]
struct Dependencies(StableDiGraph<Node, ()>);

impl Dependencies {
    fn new() -> Self {
        Self(StableDiGraph::new())
    }

    fn add_node(&mut self, a: Address) -> Ref {
        if let Some(r) = self.find_node(&a) {
            return r
        }
        Ref(self.0.add_node(Node {
            worker: a,
            status: Status::Up,
            restarter: None
        }))
    }

    fn node(&self, r: Ref) -> Option<&Node> {
        self.0.node_weight(r.0)
    }

    fn node_mut(&mut self, r: Ref) -> Option<&mut Node> {
        self.0.node_weight_mut(r.0)
    }

    fn find_node(&self, a: &Address) -> Option<Ref> {
        for i in self.0.node_indices() {
            if self.0[i].worker == *a {
                return Some(Ref(i))
            }
        }
        None
    }

    fn add_dependency(&mut self, from: Ref, to: Ref) -> bool {
        if !self.0.contains_node(from.0) || !self.0.contains_node(to.0) {
            return false
        }
        self.0.add_edge(from.0, to.0, ());
        true
    }

    fn dependencies(&self, r: Ref) -> impl Iterator<Item = (Ref, &Node)> + '_ {
        self.0.neighbors_directed(r.0, Direction::Outgoing)
            .filter_map(|r| {
                if let Some(n) = self.node(Ref(r)) {
                    Some((Ref(r), n))
                } else {
                    None
                }
            })
    }

    fn dependents(&self, r: Ref) -> impl Iterator<Item = (Ref, &Node)> + '_ {
        self.0.neighbors_directed(r.0, Direction::Incoming)
            .filter_map(|r| {
                if let Some(n) = self.node(Ref(r)) {
                    Some((Ref(r), n))
                } else {
                    None
                }
            })
    }
}

#[derive(Debug)]
pub struct Medic {
    delay: Duration,
    manager: Address,
    sessions: Sessions
}

#[derive(Debug)]
pub struct Sessions(Arc<Mutex<SessionsImpl>>);

#[derive(Debug)]
struct SessionsImpl {
    ctr: u32,
    ses: HashMap<Key, Session>,
    dep: Dependencies
}

#[derive(Debug)]
struct Session {
    addr: MultiAddr,
    route: Route,
    ptr: Ref,
    info: SecureChannelInfo,
    pings: ArrayVec<[Ping; MAX_FAILURES]>
}

#[derive(Debug, Copy, Clone, Encode, Decode)]
pub struct Message {
    #[n(0)] key: Key,
    #[n(1)] ping: Ping
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct Key {
    #[n(0)] fst: u32,
    #[n(1)] snd: u32
}

#[derive(Debug, Default, Copy, Clone, Encode, Decode, PartialEq, Eq)]
#[cbor(transparent)]
struct Ping(#[n(0)] u64);

impl Sessions {
    pub async fn add(&self, info: SecureChannelInfo) -> Result<Key, Error> {
        let mut ma = MultiAddr::default();
        ma.push_back(proto::Service::new(info.addr().address())).map_err(map_multiaddr_err)?;
        ma.push_back(proto::Service::new(Responder::NAME)).map_err(map_multiaddr_err)?;
        let mut this = self.0.lock().await;
        let n = this.ctr;
        this.ctr = this.ctr.checked_add(1).ok_or_else(|| {
            Error::new(Origin::Other, Kind::Internal, "Sessions::ctr overflow")
        })?;
        let key = Key::new(n);
        let r = crate::try_multiaddr_to_route(&ma)?;
        log::debug!(%key, addr = %ma, "add session");
        let p = this.dep.add_node(info.addr().clone());
        for a in info.route().iter().filter(|a| a.is_local() && a.address() != "api") {
            let t = this.dep.add_node(a.clone());
            this.dep.add_dependency(p, t);
        }
        let s = Session { addr: ma, route: r, ptr: p, info, pings: ArrayVec::new() };
        this.ses.insert(key, s);
        Ok(key)
    }

    // pub async fn add_dependency(&self, from: &Address, to: Address) {
    //     let mut this = self.0.lock().await;
    //     let p = this.dep.add_node(to);
    //     if let Some(r) = this.dep.find_node(from) {
    //         this.dep.add_dependency(p, r);
    //     }
    // }
}

impl Medic {
    pub fn new(manager: Address) -> Self {
        Self {
            delay: Duration::from_secs(7),
            manager,
            sessions: Sessions(Arc::new(Mutex::new(SessionsImpl {
                ctr: 0,
                ses: HashMap::new(),
                dep: Dependencies::new()
            })))
        }
    }

    pub fn sessions(&self) -> Sessions {
        Sessions(self.sessions.0.clone())
    }

    pub async fn start(self, ctx: Context) -> Result<(), Error> {
        let ctx = ctx.new_detached(Address::random_local()).await?;
        let (tx, rx) = mpsc::channel(32);
        ctx.start_worker(Collector::address(), Collector(tx)).await?;
        self.go(ctx, rx).await
    }

    async fn go(self, ctx: Context, mut rx: mpsc::Receiver<Message>) -> ! {
        let mut zombies = Vec::new();
        loop {
            log::debug!("check sessions");
            for (k, s) in &mut self.sessions.0.lock().await.ses {
                if s.pings.len() < MAX_FAILURES {
                    let m = Message::new(*k);
                    s.pings.push(m.ping);
                    log::debug!(key = %k, ping = %m.ping, "send ping");
                    let l = {
                        let v = Encodable::encode(&m).expect("message can be encoded");
                        let t = TransportMessage::v1(s.route.clone(), Collector::address(), v);
                        LocalMessage::new(t, Vec::new())
                    };
                    if let Err(e) = ctx.forward(l).await {
                        log::warn!(key = %k, ping = %m.ping, err = %e, "failed to send ping")
                    }
                } else {
                    log::warn!(key = %k, addr = %s.addr, "session unresponsive");
                    zombies.push(*k)
                }
            }
            for z in zombies.drain(..) {
                let mut sessions = self.sessions.0.lock().await;
                if let Some(p) = sessions.ses.get(&z).map(|s| s.ptr) {
                    if let Some(m) = sessions.dep.dependencies(p).find(|n| !n.1.status.is_up()) {
                        log::debug!(addr = %m.1.worker, "waiting for dependency");
                        continue
                    }
                    if let Some(mut n) = sessions.dep.node_mut(p) {
                        if n.status.is_up() {
                            if let Some(f) = &mut n.restarter {
                                n.status = Status::Starting(tokio::spawn(f()))
                            } else {
                                n.status = Status::Down
                            }
                        }
                    }
                }
            }
            time::sleep(self.delay).await;
            while let Ok(m) = rx.try_recv() {
                if let Some(s) = self.sessions.0.lock().await.ses.get_mut(&m.key) {
                    if s.pings.contains(&m.ping) {
                        log::debug!(key = %m.key, ping = %m.ping, "recv pong");
                        s.pings.clear()
                    }
                }
            }
        }
    }
}

impl Key {
    fn new(n: u32) -> Self {
        Self { fst: rand::random(), snd: n }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}{:x}", self.fst, self.snd)
    }
}

impl fmt::Display for Ping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl Message {
    fn new(k: Key) -> Self {
        Self { key: k, ping: Ping(rand::random()) }
    }
}

impl Encodable for Message {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        minicbor::to_vec(self).map_err(Error::from)
    }
}

impl Decodable for Message {
    fn decode(m: &[u8]) -> Result<Self, Error> {
        minicbor::decode(m).map_err(Error::from)
    }
}

impl ockam_core::Message for Message {}

/// A collector receives messages from a [`Responder`] and forwards them.
#[derive(Debug)]
struct Collector(mpsc::Sender<Message>);

impl Collector {
    const NAME: &'static str = "ockam.ping.collector";

    fn address() -> Address {
        Address::new(LOCAL, Self::NAME)
    }
}

#[ockam::worker]
impl Worker for Collector {
    type Message = Message;
    type Context = Context;

    async fn handle_message(&mut self, _: &mut Context, msg: Routed<Self::Message>) -> Result<(), Error> {
        if self.0.send(msg.body()).await.is_err() {
            log::debug!("collector could not send message to medic")
        }
        Ok(())
    }
}

/// A responder returns received PING messages.
#[derive(Debug)]
pub struct Responder(());

impl Responder {
    const NAME: &'static str = "ockam.ping.responder";

    pub fn new() -> Self {
        Responder(())
    }

    pub fn address() -> Address {
        Address::new(LOCAL, Self::NAME)
    }
}

#[ockam::worker]
impl Worker for Responder {
    type Message = Message;
    type Context = Context;

    async fn handle_message(&mut self, ctx: &mut Context, msg: Routed<Self::Message>) -> Result<(), Error> {
        let r = msg.return_route();
        let m = msg.body();
        log::debug!(key = %m.key, ping = %m.ping, "send pong");
        ctx.send(r, m).await
    }
}

