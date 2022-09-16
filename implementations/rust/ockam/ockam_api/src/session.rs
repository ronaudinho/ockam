mod deps;

use minicbor::{Encode, Decode};
use ockam::{Worker, TransportMessage, LocalMessage};
use ockam_core::{LOCAL, Address, Error, Routed, Encodable, Decodable, route};
use ockam_core::compat::sync::{Arc, Mutex};
use ockam_node::Context;
use ockam_node::tokio;
use ockam_node::tokio::task::JoinSet;
use ockam_node::tokio::time::{timeout, Duration};
use ockam_node::tokio::sync::mpsc;
use crate::DefaultAddress;

use self::deps::{Key, Ping, Status};
use tracing as log;

pub use self::deps::{Mode, Sessions, Session};

const MAX_FAILURES: usize = 3;
const DELAY: Duration = Duration::from_secs(7);

#[derive(Debug)]
pub struct Medic {
    delay: Duration,
    sessions: Arc<Mutex<Sessions>>,
    pings: JoinSet<(Key, Result<(), Error>)>,
    replacements: JoinSet<(Key, Result<Address, Error>)>
}

#[derive(Debug, Copy, Clone, Encode, Decode)]
pub struct Message {
    #[n(0)] key: Key,
    #[n(1)] ping: Ping
}

impl Medic {
    pub fn new() -> Self {
        Self {
            delay: DELAY,
            sessions: Arc::new(Mutex::new(Sessions::new())),
            pings: JoinSet::new(),
            replacements: JoinSet::new()
        }
    }

    pub fn sessions(&self) -> Arc<Mutex<Sessions>> {
        self.sessions.clone()
    }

    pub async fn start(self, ctx: Context) -> Result<(), Error> {
        let ctx = ctx.new_detached(Address::random_local()).await?;
        let (tx, rx) = mpsc::channel(32);
        ctx.start_worker(Collector::address(), Collector(tx)).await?;
        self.go(ctx, rx).await
    }

    async fn go(mut self, ctx: Context, mut rx: mpsc::Receiver<Message>) -> ! {
        let ctx = Arc::new(ctx);
        loop {
            log::debug!("check sessions");
            {
                let mut sessions = self.sessions.lock().unwrap();
                let (keys, graph) = sessions.parts_mut();
                for key in keys.iter() {
                    if graph.dependent_neighbours(key).find(|s| s.mode() == Mode::Active).is_some() {
                        log::debug!(%key, "skipping session with active dependent sessions");
                        continue
                    }

                    let session = graph.session_mut(key).expect("valid key");

                    if session.mode() == Mode::Passive {
                        log::debug!(%key, "skipping passive session");
                        continue
                    }

                    if session.pings().len() < MAX_FAILURES {
                        let m = Message::new(session.key());
                        session.add_ping(m.ping);
                        log::debug!(%key, ping = %m.ping, "send ping");
                        let l = {
                            let v = Encodable::encode(&m).expect("message can be encoded");
                            let r = route![session.address().clone(), DefaultAddress::ECHO_SERVICE];
                            let t = TransportMessage::v1(r, Collector::address(), v);
                            LocalMessage::new(t, Vec::new())
                        };
                        let sender = ctx.clone();
                        self.pings.spawn(async move { (key, sender.forward(l).await) });
                        continue
                    }

                    for dep in graph.dependencies(key).filter(|s| s.status() == Status::Down) {
                        log::debug!(%key, dep = %dep.key(), "waiting for dependency");
                        continue
                    }

                    let session = graph.session_mut(key).expect("valid key");

                    match session.status() {
                        Status::Up => {
                            log::debug!(%key, "session unresponsive");
                            let f = session.replacement(None);
                            session.set_status(Status::Down);
                            if let Some(k) = graph.dependencies(key).map(Session::key).last() {
                                let d = graph.session_mut(k).expect("valid key");
                                let f = d.replacement(None);
                                d.set_status(Status::Down);
                                log::debug!(%key, dep = %d.key(), "replacing session dependency root");
                                self.replacements.spawn(async move { (k, f.await) });
                            } else {
                                log::debug!(%key, "replacing session");
                                self.replacements.spawn(async move { (key, f.await) });
                            }
                        }
                        Status::Down => {
                            log::debug!(%key, "session is down");
                        }
                    }
                }
            }

            let _ = timeout(self.delay, self.get_results(&mut rx)).await;
        }
    }

    async fn get_results(&mut self, rx: &mut mpsc::Receiver<Message>) {
        loop {
            tokio::select! {
                p = self.pings.join_next(), if !self.pings.is_empty() => match p {
                    None                  => log::debug!("no pings to send"),
                    Some(Err(e))          => log::error!("task failed: {e:?}"),
                    Some(Ok((k, Err(e)))) => log::debug!(key = %k, err = %e, "failed to send ping"),
                    Some(Ok((k, Ok(())))) => log::debug!(key = %k, "sent ping"),
                },
                r = self.replacements.join_next(), if !self.replacements.is_empty() => match r {
                    None                  => log::debug!("no replacements"),
                    Some(Err(e))          => log::error!("task failed: {e:?}"),
                    Some(Ok((k, Err(e)))) => {
                        let mut sessions = self.sessions.lock().unwrap();
                        if let Some(s) = sessions.session_mut(k) {
                            log::debug!(key = %k, err = %e, "replacing session failed");
                            let f = s.replacement(None);
                            if let Some(key) = sessions.dependencies(k).map(Session::key).last() {
                                let d = sessions.session_mut(key).expect("valid key");
                                let f = d.replacement(None);
                                d.set_status(Status::Down);
                                log::debug!(key = %k, dep = %key, "replacing session dependency root (again)");
                                self.replacements.spawn(async move { (key, f.await) });
                            } else {
                                log::debug!(key = %k, "replacing session");
                                self.replacements.spawn(async move { (k, f.await) });
                            }
                        }
                    }
                    Some(Ok((k, Ok(a)))) => {
                        let mut sessions = self.sessions.lock().unwrap();
                        if let Some(s) = sessions.session_mut(k) {
                            log::debug!(key = %k, addr = %a, "replacement is up");
                            s.set_status(Status::Up);
                            s.set_address(a.clone());
                            s.clear_pings();
                            let n: Vec<Key> = sessions.dependent_neighbours(k).map(Session::key).collect();
                            for j in n {
                                let d = sessions.session_mut(j).expect("valid key");
                                let f = d.replacement(Some(a.clone()));
                                d.set_status(Status::Down);
                                log::debug!(key = %k, dep = %d.key(), "replacing dependent session");
                                self.replacements.spawn(async move { (j, f.await) });
                            }
                        }
                    }
                },
                Some(m) = rx.recv() => {
                    if let Some(s) = self.sessions.lock().unwrap().session_mut(m.key) {
                        if s.pings().contains(&m.ping) {
                            log::debug!(key = %m.key, ping = %m.ping, "recv pong");
                            s.clear_pings()
                        }
                    }
                },
                else => break
            }
        }
    }
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
