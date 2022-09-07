use core::fmt;
use minicbor::{Encode, Decode};
use ockam::Worker;
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

use crate::error::ApiError;

const MAX_FAILURES: usize = 3;

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
    pings: ArrayVec<[u64; MAX_FAILURES]>
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct Key {
    #[n(0)] fst: u32,
    #[n(1)] snd: u32
}

#[derive(Debug, Copy, Clone, Encode, Decode)]
pub struct Message {
    #[n(0)] key: Key,
    #[n(1)] ping: u64
}

impl fmt::Debug for Medic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Medic").finish()
    }
}

impl Sessions {
    pub async fn add(&self, mut addr: MultiAddr) -> Result<Key, Error> {
        let addr = {
            addr.drop_last();
            addr.push_back(proto::Service::new(Responder::NAME)).unwrap();
            addr
        };
        let mut this = self.0.lock().await;
        let n = this.0;
        this.0 = this.0.checked_add(1).ok_or_else(|| {
            Error::new(Origin::Other, Kind::Internal, "Sessions::ctr overflow")
        })?;
        let key = Key::new(n);
        log::debug!(%addr, %key, "adding session");
        let r = crate::multiaddr_to_route(&addr)
            .ok_or_else(|| ApiError::generic("invalid MultiAddr"))?;
        let s = Session { addr, route: r, pings: ArrayVec::new() };
        this.1.insert(key, s);
        Ok(key)
    }
    
    pub async fn remove(&self, key: Key) {
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
        let ctx = ctx.new_detached(Collector::address()).await?;
        let (tx, rx) = mpsc::channel(32);
        ctx.start_worker(Address::random_local(), Collector(tx)).await?;
        self.go(ctx, rx).await
    }

    async fn go(self, ctx: Context, mut rx: mpsc::Receiver<Message>) -> ! {
        loop {
            log::debug!("checking sessions");
            for (k, s) in &mut self.sessions.0.lock().await.1 {
                // s.pings.clear(); // TODO: remove
                if s.pings.len() < MAX_FAILURES {
                    let m = Message::new(*k);
                    s.pings.push(m.ping);
                    log::debug!(addr = %s.addr, ping = %m.ping, "sending ping");
                    if let Err(e) = ctx.send(s.route.clone(), m).await {
                        log::warn!(addr = %s.addr, err = %e, "failed to send ping")
                    }
                }
            }
            time::sleep(self.delay).await;
            while let Ok(m) = rx.try_recv() {
                if let Some(s) = self.sessions.0.lock().await.1.get_mut(&m.key) {
                    if s.pings.contains(&m.ping) {
                        log::debug!(addr = %s.addr, ping = m.ping, "received pong");
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

impl Message {
    fn new(k: Key) -> Self {
        Self { key: k, ping: rand::random() }
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

/// Worker collecting PONGs and delivering them to the `Medic`.
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
        log::debug!(ping = m.ping, key = %m.key, ?r, "responding to ping");
        ctx.send(r, m).await
    }
}

