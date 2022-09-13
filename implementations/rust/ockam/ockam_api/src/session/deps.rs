use core::fmt;
use core::future::Future;
use core::pin::Pin;
use ockam_core::Error;
use petgraph::stable_graph::StableDiGraph;
use petgraph::graph::NodeIndex;
use petgraph::Direction;
use crate::session::map::Key;

pub type Replacement<T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send>>;

pub struct Node<T> {
    data: T,
    key: Option<Key>,
    status: Status,
    replace: Option<Box<dyn Fn(Option<T>) -> Replacement<T> + Send>>
}

impl<T> Node<T> {
    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn is_up(&self) -> bool {
        matches!(self.status, Status::Up)
    }

    pub fn is_starting(&self) -> bool {
        matches!(self.status, Status::Starting)
    }

    pub fn down(&mut self) {
        self.status = Status::Down
    }

    pub fn starting(&mut self) {
        self.status = Status::Starting
    }

    pub fn up(&mut self, data: T) {
        self.status = Status::Up;
        self.data = data;
    }

    pub fn key(&self) -> Option<Key> {
        self.key
    }

    pub fn set_key(&mut self, k: Key) {
        self.key = Some(k)
    }

    pub fn replacement(&self, dep: Option<T>) -> Option<Replacement<T>> {
        self.replace.as_ref().map(|f| f(dep))
    }

    pub fn set_replacement<F>(&mut self, f: F)
    where
        F: Fn(Option<T>) -> Replacement<T> + Send + 'static
    {
        self.replace = Some(Box::new(f))
    }
}

impl<T: fmt::Debug> fmt::Debug for Node<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("data", &self.data)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Debug)]
enum Status { Down, Starting, Up }

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Ref(NodeIndex);

#[derive(Debug)]
pub struct Dependencies<T>(StableDiGraph<Node<T>, ()>);

impl<T: PartialEq> Dependencies<T> {
    pub fn new() -> Self {
        Self(StableDiGraph::new())
    }

    pub fn add_node(&mut self, data: T) -> Ref {
        if let Some(r) = self.find_node(&data) {
            return r
        }
        Ref(self.0.add_node(Node { data, status: Status::Up, key: None, replace: None }))
    }

    pub fn find_node(&self, a: &T) -> Option<Ref> {
        for i in self.0.node_indices() {
            if self.0[i].data == *a {
                return Some(Ref(i))
            }
        }
        None
    }

    pub fn node(&self, r: Ref) -> Option<&Node<T>> {
        self.0.node_weight(r.0)
    }

    pub fn node_mut(&mut self, r: Ref) -> Option<&mut Node<T>> {
        self.0.node_weight_mut(r.0)
    }

    pub fn add_dependency(&mut self, from: Ref, to: Ref) -> bool {
        if !self.0.contains_node(from.0) || !self.0.contains_node(to.0) {
            return false
        }
        self.0.add_edge(from.0, to.0, ());
        true
    }

    pub fn dependencies(&self, r: Ref) -> impl Iterator<Item = (Ref, &Node<T>)> + '_ {
        self.deps(r, Direction::Outgoing)
    }

    pub fn dependents(&self, r: Ref) -> impl Iterator<Item = (Ref, &Node<T>)> + '_ {
        self.deps(r, Direction::Incoming)
    }

    fn deps(&self, r: Ref, d: Direction) -> impl Iterator<Item = (Ref, &Node<T>)> + '_ {
        self.0.neighbors_directed(r.0, d)
            .filter_map(|r| {
                if let Some(n) = self.node(Ref(r)) {
                    Some((Ref(r), n))
                } else {
                    None
                }
            })
    }
}
