//! An in-memory ABAC backend implementation.

use core::fmt::{self, Debug, Formatter};

use super::{PolicyStorage, Action, Cond, Resource};
use ockam_core::Result;
use ockam_core::{
    async_trait,
    compat::{boxed::Box, collections::BTreeMap, sync::Arc, sync::RwLock},
};

#[derive(Default)]
pub struct Memory {
    pub(crate) inner: Arc<RwLock<Inner>>,
}

impl Debug for Memory {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Memory")
    }
}

impl Memory {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::new())),
        }
    }
}

#[derive(Default)]
pub struct Inner {
    policies: BTreeMap<Resource, BTreeMap<Action, Cond>>,
}

impl Inner {
    fn new() -> Self {
        Inner::default()
    }

    fn del_policy(&mut self, r: &Resource) {
        self.policies.remove(r);
    }

    fn get_policy(&self, r: &Resource, a: &Action) -> Option<Cond> {
        self.policies.get(r).and_then(|p| p.get(a).cloned())
    }

    fn set_policy(&mut self, r: Resource, a: Action, p: &Cond) {
        self.policies
            .entry(r)
            .or_insert_with(BTreeMap::new)
            .insert(a, p.clone());
    }
}

#[async_trait]
impl PolicyStorage for Memory {
    async fn del_policy(&self, r: &Resource) -> Result<()> {
        Ok(self.inner.write().unwrap().del_policy(r))
    }

    async fn get_policy(&self, r: &Resource, a: &Action) -> Result<Option<Cond>> {
        Ok(self.inner.read().unwrap().get_policy(r, a))
    }

    async fn set_policy(&self, r: Resource, a: Action, p: &Cond) -> Result<()> {
        Ok(self.inner.write().unwrap().set_policy(r, a, p))
    }
}

#[cfg(test)]
mod tests {
    use crate::mem::Memory;
    use crate::{eq, int, string, var, set, member, Action, Resource, Env};

    #[test]
    fn example1() {
        let condition = {
            let is_john       = eq(var("subject.name"), string("John"));
            let is_version1   = eq(var("resource.version"), string("1.0.0"));
            let john_is_admin = member(var("resource.admins"), string("John"));
            is_version1.and(is_john).and(john_is_admin)
        };

        let action   = Action::new("r");
        let resource = Resource::new("/foo/bar/baz");
        let store    = Memory::new();

        store.inner
            .write()
            .unwrap()
            .set_policy(resource.clone(), action.clone(), &condition);

        let mut e = Env::new();
        e.put("subject.age", int(25))
            .put("subject.name", string("John"))
            .put("resource.version", string("1.0.0"))
            .put("resource.admins", set([string("root"), string("John")]));


        let policy = store.inner.write().unwrap().get_policy(&resource, &action).unwrap();
        assert!(policy.apply(&e).unwrap());
    }
}
