use crate::authenticator::IdentityId;
use crate::Timestamp;
use minicbor::{Decode, Encode};

#[cfg(feature = "tag")]
use crate::TypeTag;

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Enroller<'a> {
    #[cfg(feature = "tag")]
    #[n(0)] tag: TypeTag<1010815>,
    #[b(1)] enroller: IdentityId<'a>
}

impl<'a> Enroller<'a> {
    pub fn new(enroller: IdentityId<'a>) -> Self {
        Enroller {
            #[cfg(feature = "tag")]
            tag: TypeTag,
            enroller,
        }
    }

    pub fn enroller(&self) -> &IdentityId {
        &self.enroller
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct EnrollerInfo {
    #[b(1)] registered_at: Timestamp
}

impl EnrollerInfo {
    pub fn new(t: Timestamp) -> Self {
        EnrollerInfo { registered_at: t }
    }

    pub fn registered_at(&self) -> Timestamp {
        self.registered_at
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct CredentialRequest<'a> {
    #[cfg(feature = "tag")]
    #[n(0)] tag: TypeTag<2820828>,
    #[b(1)] member: IdentityId<'a>
}

impl<'a> CredentialRequest<'a> {
    pub fn new(member: IdentityId<'a>) -> Self {
        CredentialRequest {
            #[cfg(feature = "tag")]
            tag: TypeTag,
            member,
        }
    }

    pub fn member(&self) -> &IdentityId {
        &self.member
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct MemberCredential<'a> {
    #[n(0)] issued_at: Timestamp,
    #[b(1)] member: IdentityId<'a>
}

impl<'a> MemberCredential<'a> {
    pub fn new(t: Timestamp, member: IdentityId<'a>) -> Self {
        MemberCredential {
            issued_at: t,
            member,
        }
    }

    pub fn member(&self) -> &IdentityId {
        &self.member
    }

    pub fn issued_at(&self) -> Timestamp {
        self.issued_at
    }
}
