use crate::{Error, Meta, Signature, Signer, Tag, Verifier};
use ed25519_dalek as ed25519;
use minicbor::decode::{self, Decoder};
use minicbor::encode::{self, Encoder, Write};
use minicbor::{Decode, Encode};
use rand::{self, RngCore};

pub const ED25519: Tag = Tag(3);

pub struct SecKey(ed25519::Keypair);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubKey(ed25519::PublicKey);

impl SecKey {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut gen = rand::thread_rng();
        let mut bytes = [0; 32];
        gen.fill_bytes(&mut bytes);
        let sk = ed25519::SecretKey::from_bytes(&bytes).unwrap();
        let pk = ed25519::PublicKey::from(&sk);
        let kp = ed25519::Keypair {
            secret: sk,
            public: pk,
        };
        SecKey(kp)
    }

    pub fn pubkey(&self) -> PubKey {
        PubKey(self.0.public)
    }
}

impl Signer for SecKey {
    fn sign(&self, data: &[u8]) -> Result<Signature, Error> {
        use ed25519_dalek::Signer;
        let s = self.0.try_sign(data).map_err(Error::message)?;
        Ok(Signature::new(s.to_bytes()))
    }
}

impl Meta for PubKey {
    const TAG: Tag = ED25519;
}

impl Verifier for PubKey {
    fn is_valid(&self, data: &[u8], sig: &Signature) -> bool {
        let a = if let Ok(s) = <[u8; 64]>::try_from(sig.data()) {
            s
        } else {
            return false;
        };
        let s = ed25519::Signature::from(a);
        ed25519::Verifier::verify(&self.0, data, &s).is_ok()
    }
}

impl<C> Encode<C> for PubKey {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), encode::Error<W::Error>> {
        e.bytes(self.0.as_bytes())?.ok()
    }
}

impl<'b, C> Decode<'b, C> for PubKey {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, decode::Error> {
        let p = d.position();
        let b = d.bytes()?;
        let p = ed25519::PublicKey::from_bytes(b).map_err(|e| decode::Error::message(e).at(p))?;
        Ok(PubKey(p))
    }
}
