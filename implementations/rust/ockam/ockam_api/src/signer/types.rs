use core::fmt;
use data_encoding::BASE32_DNSSEC;
use crate::authenticator::IdentityId;
use crate::CowBytes;
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
        Signed {
            dat: CowBytes(data.into()),
            sig,
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.dat
    }

    pub fn signature(&self) -> &Signature {
        &self.sig
    }
}

impl fmt::Display for Signed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = minicbor::to_vec(self).expect("Signed::encode does not fail");
        write!(f, "{}", BASE32_DNSSEC.encode(&bytes))
    }
}

/// A detached signature.
#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
pub struct Signature<'a> {
    /// The key ID that was used to sign the data.
    #[b(0)] ident: IdentityId<'a>,
    /// The signature bytes.
    #[b(1)] signature: CowBytes<'a>
}

impl<'a> Signature<'a> {
    pub fn new<S>(id: IdentityId<'a>, sig: S) -> Self
    where
        S: Into<Cow<'a, [u8]>>,
    {
        Signature {
            ident: id,
            signature: CowBytes(sig.into()),
        }
    }

    pub fn identity(&self) -> &IdentityId {
        &self.ident
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}
