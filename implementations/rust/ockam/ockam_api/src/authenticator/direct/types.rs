use crate::{CowStr, Timestamp};
use minicbor::{Decode, Encode};
use ockam_core::compat::borrow::Cow;

#[cfg(feature = "tag")]
use crate::TypeTag;

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Enroller<'a> {
    #[cfg(feature = "tag")]
    #[n(0)] tag: TypeTag<1010815>,
    #[b(1)] enroller: CowStr<'a>
}

impl<'a> Enroller<'a> {
    pub fn new<S: Into<Cow<'a, str>>>(enroller: S) -> Self {
        Enroller {
            #[cfg(feature = "tag")]
            tag: TypeTag,
            enroller: CowStr(enroller.into())
        }
    }

    pub fn enroller(&self) -> &str {
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
    #[b(1)] member: CowStr<'a>
}

impl<'a> CredentialRequest<'a> {
    pub fn new<S: Into<Cow<'a, str>>>(member: S) -> Self {
        CredentialRequest {
            #[cfg(feature = "tag")]
            tag: TypeTag,
            member: CowStr(member.into())
        }
    }

    pub fn member(&self) -> &str {
        &self.member
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct MemberCredential<'a> {
    #[n(0)] issued_at: Timestamp,
    #[b(1)] member: CowStr<'a>
}

impl<'a> MemberCredential<'a> {
    pub fn new<S: Into<Cow<'a, str>>>(t: Timestamp, m: S) -> Self {
        MemberCredential { issued_at: t, member: CowStr(m.into()) }
    }

    pub fn member(&self) -> &str {
        &self.member
    }

    pub fn issued_at(&self) -> Timestamp {
        self.issued_at
    }
}

