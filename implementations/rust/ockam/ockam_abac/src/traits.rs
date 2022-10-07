use crate::policy::Cond;
use crate::types::{Resource, Action};

use ockam_core::Result;
use ockam_core::async_trait;

#[async_trait]
pub trait PolicyStorage: Send + Sync + 'static {
    async fn del_policy(&self, r: &Resource) -> Result<()>;
    async fn get_policy(&self, r: &Resource, a: &Action) -> Result<Option<Cond>>;
    async fn set_policy(&self, r: Resource, a: Action, c: &Cond) -> Result<()>;
}
