use crate::{CowBytes, CowStr};
use minicbor::{Decode, Encode};
use ockam_core::compat::borrow::Cow;

/// Signed data.
#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
pub struct Signed<'a> {
    /// The data.
    #[b(0)] dat: CowBytes<'a>,
    /// The detached signature.
    #[b(1)] sig: Signature<'a>
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
pub struct Signature<'a> {
    /// The key ID that was used to sign the data.
    #[b(0)] key_id: CowStr<'a>,
    /// The signature bytes.
    #[b(1)] signature: CowBytes<'a>
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

