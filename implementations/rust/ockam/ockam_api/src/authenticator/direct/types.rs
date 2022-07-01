use crate::{CowStr, Timestamp};
use minicbor::{Decode, Encode};
use ockam_core::compat::borrow::Cow;

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Enroller<'a> {
    #[b(1)] enroller: CowStr<'a>
}

impl<'a> Enroller<'a> {
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
    #[b(1)] member: CowStr<'a>
}

impl CredentialRequest<'_> {
    pub fn member(&self) -> &str {
        &self.member
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct MemberCredential<'a> {
    #[n(1)] issued_at: Timestamp,
    #[b(2)] member: CowStr<'a>
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

