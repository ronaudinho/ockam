use crate::{Error, Meta, Signature, Signer, Tag, Verifier};
use minicbor::decode::{self, Decoder};
use minicbor::encode::{self, Encoder, Write};
use minicbor::{Decode, Encode};
use ssh_key::{Algorithm, HashAlg};
use std::fs;
use std::path::Path;

pub const SSH: Tag = Tag(2);

pub struct SecKey(ssh_key::PrivateKey);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubKey(ssh_key::PublicKey);

impl SecKey {
    pub fn new<T: AsRef<[u8]>>(sec_key: T) -> Result<Self, Error> {
        let k = ssh_key::PrivateKey::from_openssh(sec_key)?;
        Ok(SecKey(k))
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let b = fs::read_to_string(path)?;
        Self::new(b)
    }
}

impl Signer for SecKey {
    fn sign(&self, data: &[u8]) -> Result<Signature, Error> {
        let s = signature::Signer::try_sign(&self.0, data).map_err(Error::message)?;
        #[rustfmt::skip]
        let a = match s.algorithm() {
            Algorithm::Ed25519                             => 0,
            Algorithm::Rsa { hash: None }                  => 1,
            Algorithm::Rsa { hash: Some(HashAlg::Sha256) } => 2,
            Algorithm::Rsa { hash: Some(HashAlg::Sha512) } => 3,
            _ => return Err(Error::message("unsupported signature algorithm"))
        };
        let mut b = vec![a];
        b.extend_from_slice(s.as_bytes());
        Ok(Signature::new(b))
    }
}

impl PubKey {
    pub fn new<T: AsRef<str>>(pubkey: T) -> Result<Self, Error> {
        let mut k = ssh_key::PublicKey::from_openssh(pubkey.as_ref())?;
        k.set_comment("");
        Ok(PubKey(k))
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let b = fs::read_to_string(path)?;
        Self::new(b)
    }
}

impl Meta for PubKey {
    const TAG: Tag = SSH;
}

impl Verifier for PubKey {
    fn is_valid(&self, data: &[u8], sig: &Signature) -> bool {
        #[rustfmt::skip]
        let a = match sig.data().get(0) {
            Some(0) => ssh_key::Algorithm::Ed25519,
            Some(1) => ssh_key::Algorithm::Rsa { hash: None },
            Some(2) => ssh_key::Algorithm::Rsa { hash: Some(ssh_key::HashAlg::Sha256) },
            Some(3) => ssh_key::Algorithm::Rsa { hash: Some(ssh_key::HashAlg::Sha512) },
            _       => return false
        };
        let s = if let Ok(s) = ssh_key::Signature::new(a, &sig.data()[1..]) {
            s
        } else {
            return false;
        };
        signature::Verifier::verify(&self.0, data, &s).is_ok()
    }
}

impl<C> Encode<C> for PubKey {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), encode::Error<W::Error>> {
        let b = &self.0.to_bytes().map_err(encode::Error::message)?;
        e.bytes(b)?.ok()
    }
}

impl<'b, C> Decode<'b, C> for PubKey {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, decode::Error> {
        let p = d.position();
        let b = d.bytes()?;
        let p = ssh_key::PublicKey::from_bytes(b).map_err(|e| decode::Error::message(e).at(p))?;
        Ok(PubKey(p))
    }
}
