use crate::{CowBytes, CowStr};
use ockam_core::vault::PublicKey;
use minicbor::{Decode, Encode};
use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

/// The various kinds of signing requests an authority handles.
#[derive(Debug, Decode, Encode)]
#[cbor(map)]
pub enum CredentialRequest<'a> {
    /// Sign an OAuth2 user profile.
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

/// Signed data.
#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Signed<'a> {
    /// The data.
    #[b(1)] dat: CowBytes<'a>,
    /// The detached signature.
    #[b(2)] sig: Signature<'a>
}

impl<'a> Signed<'a> {
    pub fn new<D: Into<Cow<'a, [u8]>>>(data: D, sig: Signature<'a>) -> Self {
        Signed { dat: CowBytes(data.into()), sig }
    }
    
    pub fn data(&self) -> &[u8] {
        &self.dat
    }
    
    pub fn signature(&self) -> &Signature {
        &self.sig
    }
}

/// A detached signature.
#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Signature<'a> {
    /// The key ID that was used to sign the data.
    #[b(1)] key_id: CowStr<'a>,
    /// The signature bytes.
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

/// OAuth2 access token data.
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

/// A membership credential.
#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Membership<'a> {
    /// The time when this credential was issues.
    #[n(1)] issued_at: Timestamp,
    /// The member's key ID.
    #[b(2)] key_id: &'a str,
    /// The member's public key.
    #[n(3)] public: PublicKey,
    /// The member's attributes.
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
    
    pub fn issued_at(&self) -> Timestamp {
        self.issued_at
    }
    
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    
    pub fn pubkey(&self) -> &PublicKey {
        &self.public
    }
    
    pub fn attributes(&self) -> Option<&str> {
        self.attributes.as_deref()
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

