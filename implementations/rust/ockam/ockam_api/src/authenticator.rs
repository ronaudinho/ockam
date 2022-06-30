#[cfg(feature = "direct-authenticator")]
pub mod direct;

#[cfg(feature = "oauth2-authenticator")]
pub mod oauth2;

use crate::CowStr;
use minicbor::{Encode, Decode};
use ockam_core::compat::borrow::Cow;
use ockam_identity::IdentityIdentifier;

#[derive(Clone, Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct IdentityId<'a>(#[b(0)] pub CowStr<'a>);

impl<'a> IdentityId<'a> {
    pub fn new<S: Into<Cow<'a, str>>>(id: S) -> Self {
        IdentityId(CowStr(id.into()))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'a> From<&'a IdentityIdentifier> for IdentityId<'a> {
    fn from(id: &'a IdentityIdentifier) -> Self {
        IdentityId::new(id.key_id())
    }
}

impl From<IdentityIdentifier> for IdentityId<'_> {
    fn from(id: IdentityIdentifier) -> Self {
        IdentityId::new(id.key_id().clone())
    }
}

