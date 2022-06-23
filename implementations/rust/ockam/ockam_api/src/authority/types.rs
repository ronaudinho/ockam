use crate::{CowBytes, CowStr};
use ockam_core::vault::PublicKey;
use minicbor::{Decode, Encode};
use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
pub enum CredentialRequest<'a> {
    #[n(1)] Oauth2 {
        #[b(1)] dat: CowBytes<'a>,
        #[b(2)] sig: Signature<'a>
    },
    #[n(2)] CreateSpace {
        #[b(1)] dat: CowBytes<'a>,
        #[b(2)] sig: Signature<'a>
    },
    #[n(3)] CreateProject {
        #[b(1)] dat: CowBytes<'a>,
        #[b(2)] sig: Signature<'a>
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
pub struct Signed<'a> {
    #[b(1)] dat: CowBytes<'a>,
    #[b(2)] sig: Signature<'a>
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
pub struct Signature<'a> {
    #[b(1)] key_id: CowStr<'a>,
    #[b(2)] signature: CowBytes<'a>
}

impl Signature<'_> {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
pub struct Oauth2<'a> {
    #[b(1)] access_token: CowStr<'a>
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
pub struct CreateSpace<'a> {
    #[b(1)] name: CowStr<'a>
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
pub struct CreateProject<'a> {
    #[b(1)] name: CowStr<'a>
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Membership<'a> {
    #[n(1)] issued_at: Timestamp,
    #[b(2)] key_id: CowStr<'a>,
    #[n(3)] public: Cow<'a, PublicKey>,
    #[b(4)] attributes: Option<CowStr<'a>>
}

impl<'a> Membership<'a> {
    pub fn new<S>(time: Timestamp, key_id: S, key: Cow<'a, PublicKey>) -> Self
    where
        S: Into<Cow<'a, str>>
    {
        Membership {
            issued_at: time,
            key_id: CowStr(key_id.into()),
            public: key,
            attributes: None
        }
    }
    
    pub fn with_attributes<E: Into<Cow<'a, str>>>(self, attrs: E) -> Self {
        Membership {
            attributes: Some(CowStr(attrs.into())),
            .. self
        }
    }
}

#[derive(Debug, Clone, Copy, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cbor(transparent)]
pub struct Timestamp(#[n(0)] u64);

impl Timestamp {
    pub fn now() -> Option<Self> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| Timestamp(d.as_secs()))
    }
}

impl From<Timestamp> for u64 {
    fn from(t: Timestamp) -> Self {
        t.0
    }
}

