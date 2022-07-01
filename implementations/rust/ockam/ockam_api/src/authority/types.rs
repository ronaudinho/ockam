use crate::{CowBytes, CowStr};
use ockam_core::vault::PublicKey;
use minicbor::{Decode, Encode};
use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Decode, Encode)]
#[cbor(map)]
pub enum CredentialRequest<'a> {
    #[cbor(n(1))]
    Oauth2 {
        #[cbor(b(1), with = "minicbor::bytes")]
        data: &'a [u8],

        #[cbor(b(2))]
        signature: Signature<'a>
    },
    #[cbor(n(2))]
    CreateSpace {
        #[cbor(b(1), with = "minicbor::bytes")]
        data: &'a [u8],

        #[cbor(b(2))]
        signature: Signature<'a>
    },
    #[cbor(n(3))]
    CreateProject {
        #[cbor(b(1), with = "minicbor::bytes")]
        data: &'a [u8],

        #[cbor(b(2))]
        signature: Signature<'a>
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Signed<'a> {
    #[b(1)] dat: CowBytes<'a>,
    #[b(2)] sig: Signature<'a>
}

impl<'a> Signed<'a> {
    pub fn new<D: Into<Cow<'a, [u8]>>>(data: D, sig: Signature<'a>) -> Self {
        Signed { dat: CowBytes(data.into()), sig }
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Signature<'a> {
    #[b(1)] key_id: CowStr<'a>,
    #[b(2)] signature: CowBytes<'a>
}

impl<'a> Signature<'a> {
    pub fn new<K, S>(id: K, sig: S) -> Self
    where
        K: Into<Cow<'a, str>>,
        S: Into<Cow<'a, [u8]>>
    {
        Signature {
            key_id: CowStr(id.into()),
            signature: CowBytes(sig.into())
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Oauth2<'a> {
    #[b(1)] access_token: &'a str
}

impl<'a> Oauth2<'a> {
    pub fn new(tk: &'a str) -> Self {
        Oauth2 { access_token: tk }
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct CreateSpace<'a> {
    #[b(1)] name: &'a str
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct CreateProject<'a> {
    #[b(1)] name: &'a str
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Membership<'a> {
    #[n(1)] issued_at: Timestamp,
    #[b(2)] key_id: &'a str,
    #[n(3)] public: PublicKey,
    #[b(4)] attributes: Option<&'a str>
}

impl<'a> Membership<'a> {
    pub fn new(time: Timestamp, key_id: &'a str, key: PublicKey) -> Self {
        Membership {
            issued_at: time,
            key_id,
            public: key,
            attributes: None
        }
    }
    
    pub fn with_attributes(self, attrs: &'a str) -> Self {
        Membership {
            attributes: Some(attrs),
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

