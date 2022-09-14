use core::fmt;
use core::future::Future;
use core::pin::Pin;
use std::ops::{Deref, DerefMut};
use minicbor::{Encode, Decode};
use ockam_core::{Address, Error};
use ockam_core::compat::rand;
use ockam_core::compat::collections::HashSet;
use petgraph::Direction;
use petgraph::stable_graph::StableDiGraph;
use petgraph::graph::NodeIndex;
use petgraph::visit::{Bfs, Reversed, Walker};
use tracing as log;

pub type Replacement = Pin<Box<dyn Future<Output = Result<Address, Error>> + Send>>;

pub struct Session {
    key: Key,
    address: Address,
    status: Status,
    replace: Box<dyn Fn(Option<Address>) -> Replacement + Send>,
    pings: Vec<Ping>
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("key", &self.key)
            .field("address", &self.address)
            .field("status", &self.status)
            .field("pings", &self.pings)
            .finish()
    }
}

impl Session {
    pub fn new(addr: Address) -> Self {
        Self {
            key: Key::default(),
            address: addr.clone(),
            status: Status::Up,
            replace: Box::new(move |_| {
                let addr = addr.clone();
                Box::pin(async move { Ok(addr) })
            }),
            pings: Vec::new()
        }
    }

    pub fn key(&self) -> Key {
        self.key
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn set_address(&mut self, a: Address) {
        self.address = a
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn set_status(&mut self, s: Status) {
        self.status = s
    }

    pub fn replacement(&self, a: Option<Address>) -> Replacement {
        (self.replace)(a)
    }

    pub fn set_replacement<F>(&mut self, f: F)
    where
        F: Fn(Option<Address>) -> Replacement + Send + 'static
    {
        self.replace = Box::new(f)
    }

    pub fn pings(&self) -> &[Ping] {
        &self.pings
    }

    pub fn add_ping(&mut self, p: Ping) {
        self.pings.push(p);
    }

    pub fn clear_pings(&mut self) {
        self.pings.clear()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status { Down, Up }

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct Key {
    #[n(0)] rnd: u32,
    #[n(1)] idx: usize
}

impl Key {
    fn new(n: NodeIndex) -> Self {
        Self { rnd: rand::random(), idx: n.index() }
    }

    fn idx(&self) -> NodeIndex {
        NodeIndex::new(self.idx)
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:x},{:x})", self.rnd, self.idx)
    }
}

#[derive(Debug, Default, Copy, Clone, Encode, Decode, PartialEq, Eq)]
#[cbor(transparent)]
pub struct Ping(#[n(0)] u64);

impl Ping {
    pub fn new() -> Self {
        Self(rand::random())
    }
}

impl fmt::Display for Ping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

#[derive(Debug)]
pub struct Sessions {
    keys: KeySet,
    graph: Graph
}

#[derive(Debug)]
pub struct KeySet(HashSet<Key>);

#[derive(Debug)]
pub struct Graph(StableDiGraph<Session, ()>);

impl Sessions {
    pub fn new() -> Self {
        Self {
            keys: KeySet(HashSet::new()),
            graph: Graph(StableDiGraph::new())
        }
    }

    pub fn add(&mut self, s: Session) -> Key {
        let k = Key::new(self.graph.0.add_node(s));
        self.keys.0.insert(k);
        let s = self.graph.0.node_weight_mut(k.idx()).expect("valid node index");
        log::debug! {
            target: "ockam_api::session",
            key = %k,
            addr = %s.address(),
            "session added"
        }
        s.key = k;
        k
    }

    pub fn parts_mut(&mut self) -> (&mut KeySet, &mut Graph) {
        (&mut self.keys, &mut self.graph)
    }
}

impl Deref for Sessions {
    type Target = Graph;

    fn deref(&self) -> &Self::Target {
        &self.graph
    }
}

impl DerefMut for Sessions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.graph
    }
}

impl Graph {
    pub fn session(&self, k: Key) -> Option<&Session> {
        self.0.node_weight(k.idx())
    }

    pub fn session_mut(&mut self, k: Key) -> Option<&mut Session> {
        self.0.node_weight_mut(k.idx())
    }

    pub fn add_dependency(&mut self, from: Key, to: Key) -> bool {
        if !self.0.contains_node(from.idx()) || !self.0.contains_node(to.idx()) {
            return false
        }
        self.0.add_edge(from.idx(), to.idx(), ());
        log::debug!{
            target: "ockam_api::session",
            from = %from,
            to = %to,
            "dependency added"
        }
        true
    }

    pub fn dependencies(&self, start: Key) -> impl Iterator<Item = &Session> + '_ {
        Bfs::new(&self.0, start.idx())
            .iter(&self.0)
            .skip(1)
            .map(|i| self.0.node_weight(i).expect("valid node index"))
    }

    pub fn dependents(&self, start: Key) -> impl Iterator<Item = &Session> + '_ {
        Bfs::new(&self.0, start.idx())
            .iter(Reversed(&self.0))
            .skip(1)
            .map(|i| self.0.node_weight(i).expect("valid node index"))
    }

    pub fn dependency_neighbours(&self, start: Key) -> impl Iterator<Item = &Session> + '_ {
        self.0.neighbors_directed(start.idx(), Direction::Outgoing)
            .map(|i| self.0.node_weight(i).expect("valid node index"))
    }

    pub fn dependent_neighbours(&self, start: Key) -> impl Iterator<Item = &Session> + '_ {
        self.0.neighbors_directed(start.idx(), Direction::Incoming)
            .map(|i| self.0.node_weight(i).expect("valid node index"))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Session> + '_ {
        self.0.node_weights()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Session> + '_ {
        self.0.node_weights_mut()
    }
}

impl KeySet {
    pub fn iter(&self) -> impl Iterator<Item = Key> + '_ {
        self.0.iter().copied()
    }
}
