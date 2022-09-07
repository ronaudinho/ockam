use core::fmt;
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
use ockam_node::tokio::time::{self, Duration};
use ockam_node::tokio::sync::mpsc;
use ockam_node::tokio::sync::Mutex;
use tinyvec::ArrayVec;
use tracing as log;

const MAX_FAILURES: usize = 3;

#[derive(Debug)]
pub struct Medic {
    delay: Duration,
    sessions: Sessions
}

#[derive(Debug)]
pub struct Sessions(Arc<Mutex<(u32, HashMap<Key, Session>)>>);

#[derive(Debug)]
struct Session {
    addr: MultiAddr,
    route: Route,
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

#[derive(Debug)]
pub enum SessionAddr {
    SecureChannel(MultiAddr)
}

impl From<SessionAddr> for MultiAddr {
    fn from(sa: SessionAddr) -> Self {
        match sa {
            SessionAddr::SecureChannel(ma) => ma
        }
    }
}

impl Sessions {
    pub async fn add(&self, addr: SessionAddr) -> Result<Key, Error> {
        let mut addr: MultiAddr = addr.into();
        addr.push_back(proto::Service::new(Responder::NAME)).map_err(map_multiaddr_err)?;
        let mut this = self.0.lock().await;
        let n = this.0;
        this.0 = this.0.checked_add(1).ok_or_else(|| {
            Error::new(Origin::Other, Kind::Internal, "Sessions::ctr overflow")
        })?;
        let key = Key::new(n);
        let r = crate::try_multiaddr_to_route(&addr)?;
        log::debug!(%key, %addr, "add session");
        let s = Session { addr, route: r, pings: ArrayVec::new() };
        this.1.insert(key, s);
        Ok(key)
    }

    pub async fn remove(&self, key: Key) {
        log::debug!(%key, "remove session");
        self.0.lock().await.1.remove(&key);
    }
}

impl Medic {
    pub fn new() -> Self {
        let s = Sessions(Arc::new(Mutex::new((0, HashMap::new()))));
        Self {
            delay: Duration::from_secs(7),
            sessions: s
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
        loop {
            log::debug!("check sessions");
            for (k, s) in &mut self.sessions.0.lock().await.1 {
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
                    log::warn!(key = %k, addr = %s.addr, "session unresponsive")
                }
            }
            time::sleep(self.delay).await;
            while let Ok(m) = rx.try_recv() {
                if let Some(s) = self.sessions.0.lock().await.1.get_mut(&m.key) {
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

