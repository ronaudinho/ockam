mod deps;
mod map;

use minicbor::{Encode, Decode};
use ockam::{Worker, TransportMessage, LocalMessage};
use ockam_core::{LOCAL, Address, Error, Routed, Encodable, Decodable};
use ockam_node::{Context, NodeMessage, RelayMessage};
use ockam_node::channel_types::{SmallSender, small_channel};
use ockam_node::tokio;
use ockam_node::tokio::task::JoinSet;
use ockam_node::tokio::time::{self, Duration};
use ockam_node::tokio::sync::mpsc;
use tracing as log;
use deps::{Dependencies, Ref};
use map::{MAX_FAILURES, Key, Ping};

pub use map::SessionMap;

#[derive(Debug)]
pub struct Medic {
    delay: Duration,
    sessions: SessionMap,
    pings: JoinSet<Result<(), Error>>,
    replacements: JoinSet<Address>
}

#[derive(Debug, Copy, Clone, Encode, Decode)]
pub struct Message {
    #[n(0)] key: Key,
    #[n(1)] ping: Ping
}

impl Medic {
    pub fn new() -> Self {
        Self {
            delay: Duration::from_secs(7),
            sessions: SessionMap::new(),
            pings: JoinSet::new(),
            replacements: JoinSet::new()
        }
    }

    pub fn sessions(&self) -> SessionMap {
        self.sessions.clone()
    }

    pub async fn start(self, ctx: Context) -> Result<(), Error> {
        let ctx = ctx.new_detached(Address::random_local()).await?;
        let (tx, rx) = mpsc::channel(32);
        ctx.start_worker(Collector::address(), Collector(tx)).await?;
        self.go(ctx, rx).await
    }

    async fn go(mut self, ctx: Context, mut rx: mpsc::Receiver<Message>) -> ! {
        loop {
            log::debug!("check sessions");
            {
                let mut sessions = self.sessions.0.lock().unwrap();
                let (ses, dep) = sessions.split_borrow();
                for (k, s) in ses {
                    if s.pings.len() < MAX_FAILURES {
                        let m = Message::new(*k);
                        s.pings.push(m.ping);
                        log::debug!(key = %k, ping = %m.ping, "send ping");
                        let l = {
                            let v = Encodable::encode(&m).expect("message can be encoded");
                            let t = TransportMessage::v1(s.route.clone(), Collector::address(), v);
                            LocalMessage::new(t, Vec::new())
                        };
                        self.pings.spawn(forward(ctx.sender().clone(), l));
                    } else {
                        log::warn!(key = %k, addr = %s.addr, "session unresponsive");
                        if let Some(m) = dep.dependencies(s.ptr).find(|n| !n.1.is_up()) {
                            log::debug!(key = %k, addr = %s.addr, dep = %m.1.data(), "waiting for dependency");
                            continue
                        }
                        if let Some(n) = dep.node_mut(s.ptr) {
                            if n.is_up() {
                                n.down();
                                if let Some(f) = n.replacement(None) {
                                    self.replacements.spawn(f);
                                }
                            }
                        }
                    }
                }
            }

            time::timeout(self.delay, self.get_results(&mut rx)).await;
        }
    }

    async fn get_results(&mut self, rx: &mut mpsc::Receiver<Message>) {
        loop {
            tokio::select! {
                p = self.pings.join_next(), if !self.pings.is_empty() => match p {
                    Some(Err(e)) => log::error!("task failed: {e:?}"),
                    Some(Ok(Err(e))) => log::debug!("failed to send ping: {e}"),
                    Some(Ok(Ok(()))) => log::debug!("sent ping"),
                    None => log::debug!("no pings to send")
                },
                r = self.replacements.join_next(), if !self.replacements.is_empty() => match r {
                    Some(Err(e)) => log::error!("task failed: {e:?}"),
                    Some(Ok(a)) => log::debug!("received replacement: {a}"),
                    None => log::debug!("no replacements")
                },
                p = rx.recv() => {
                    log::debug!("received pong");
                },
                else => break
            }
        }
    }
}

async fn forward(sender: SmallSender<NodeMessage>, msg: LocalMessage) -> Result<(), Error> {
    // First resolve the next hop in the route
    let (reply_tx, mut reply_rx) = small_channel();
    let next = msg.transport().onward_route.next().unwrap(); // TODO: communicate bad routes
    let req = NodeMessage::SenderReq(next.clone(), reply_tx);
    sender
        .send(req)
        .await
        .unwrap(); // TODO
    let (addr, sender, needs_wrapping) = reply_rx
        .recv()
        .await
        .unwrap() // TODO
        .unwrap() // TODO
        .take_sender()?;

    let onward = msg.transport().onward_route.clone();
    let msg = RelayMessage::new(addr, msg, onward, needs_wrapping);
    sender.send(msg).await.unwrap(); // TODO

    Ok(())
}

impl Message {
    fn new(k: Key) -> Self {
        Self { key: k, ping: Ping::new() }
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

