use core::fmt;
use crate::nodes::registry::SecureChannelInfo;
use crate::nodes::service::map_multiaddr_err;
use minicbor::{Encode, Decode};
use ockam_core::{Address, Error, Route};
use ockam_core::compat::sync::{Arc, Mutex};
use ockam_core::compat::collections::HashMap;
use ockam_core::compat::rand;
use ockam_core::errcode::{Kind, Origin};
use ockam_multiaddr::{MultiAddr, proto};
use tinyvec::ArrayVec;
use crate::session::{Dependencies, Ref, Replacement};
use crate::session::Responder;
use tracing as log;

pub const MAX_FAILURES: usize = 3;

#[derive(Debug, Clone)]
pub struct SessionMap(pub(super) Arc<Mutex<SessionMapImpl>>);

#[derive(Debug)]
pub(super) struct SessionMapImpl {
    ctr: u32,
    pub(super) ses: HashMap<Key, Session>,
    pub(super) dep: Dependencies<Address>
}

impl SessionMapImpl {
    pub(super) fn split_borrow(&mut self) -> (&mut HashMap<Key, Session>, &mut Dependencies<Address>) {
        (&mut self.ses, &mut self.dep)
    }
}

#[derive(Debug)]
pub struct Session {
    pub(super) addr: Address,
    pub(super) route: Route,
    pub(super) ptr: Ref,
    pub(super) pings: ArrayVec<[Ping; MAX_FAILURES]>
}

impl SessionMap {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(SessionMapImpl {
            ctr: 0,
            ses: HashMap::new(),
            dep: Dependencies::new()
        })))
    }

    pub fn add(&self, info: &SecureChannelInfo) -> Result<Key, Error> {
        let mut ma = MultiAddr::default();
        ma.push_back(proto::Service::new(info.addr().address())).map_err(map_multiaddr_err)?;
        ma.push_back(proto::Service::new(Responder::NAME)).map_err(map_multiaddr_err)?;
        let r = crate::try_multiaddr_to_route(&ma)?;
        let mut this = self.0.lock().unwrap();
        if this.ses.values().find(|s| &s.addr == info.addr()).is_some() {
            return Err(todo!())
        }
        let n = this.ctr;
        this.ctr = this.ctr.checked_add(1).ok_or_else(|| {
            Error::new(Origin::Other, Kind::Internal, "Sessions::ctr overflow")
        })?;
        let key = Key::new(n);
        log::debug!(%key, addr = %info.addr(), "add session");
        let p = this.dep.add_node(info.addr().clone());
        this.dep.node_mut(p).unwrap().set_key(key); // TODO
        for a in info.route().iter() {
            let t = this.dep.add_node(a.clone());
            this.dep.add_dependency(p, t);
            log::debug!(%key, addr = %info.addr(), dep = %a, "depends on");
        }
        let s = Session {
            addr: info.addr().clone(),
            route: r,
            ptr: p,
            pings: ArrayVec::new()
        };
        this.ses.insert(key, s);
        Ok(key)
    }

    pub fn set_replacement<F>(&self, k: Key, f: F)
    where
        F: Fn(Option<Address>) -> Replacement<Address> + Send + 'static
    {
        let mut this = self.0.lock().unwrap();
        let (ses, dep) = this.split_borrow();
        if let Some(s) = ses.get_mut(&k) {
            if let Some(n) = dep.node_mut(s.ptr) {
                n.set_replacement(f)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct Key {
    #[n(0)] fst: u32,
    #[n(1)] snd: u32
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

