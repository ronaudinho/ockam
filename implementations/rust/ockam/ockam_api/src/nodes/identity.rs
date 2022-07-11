use crate::authenticator::IdentityId;
use minicbor::{Decode, Encode};

#[cfg(feature = "tag")]
use ockam_core::TypeTag;

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct IdentityInfo<'a> {
    #[cfg(feature = "tag")]
    #[n(0)] tag: TypeTag<221914>,
    #[b(1)] id: IdentityId<'a>
}


impl<'a> IdentityInfo<'a> {
    pub fn new(id: IdentityId<'a>) -> Self {
        IdentityInfo {
            #[cfg(feature = "tag")]
            tag: TypeTag,
            id
        }
    }
    
    pub fn identity(&self) -> &IdentityId {
        &self.id
    }
}

