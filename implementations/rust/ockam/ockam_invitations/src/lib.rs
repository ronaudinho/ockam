mod error;

pub mod identity;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "ssh")]
pub mod ssh;

#[cfg(feature = "github")]
pub mod github;

pub use error::Error;

use minicbor::{Decode, Decoder, Encode, Encoder};

/// A type with a runtime tag.
///
/// Tagging is used to restore type information when decoding structures.
pub trait Meta {
    const TAG: Tag;
}

impl<M: Meta> Meta for &M {
    const TAG: Tag = M::TAG;
}

/// Top-leven data structure that is exchanged between parties.
///
/// Contains the actual data and a sequence of signatures of this data.
#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct Envelope {
    /// The payload data.
    #[cbor(n(1), with = "minicbor::bytes")]
    data: Vec<u8>,

    /// Signatures of the payload.
    #[cbor(n(2))]
    sign: Vec<Signature>,
}

/// The header that precedes the invitation.
///
/// When receiving an invitation the recipient needs to inspect the data to
/// figure out what kind of invitation this is. After analysing the header
/// the recipient has enough information to determine the invitation type.
#[derive(Debug, Encode, Decode, PartialEq, Eq)]
#[rustfmt::skip]
#[cbor(map)]
pub enum Header {
    /// An invite.
    #[n(1)] Invite {
        /// The initiator's public key type tag.
        #[n(1)] identity: Tag,
        /// The initiator's identifying information.
        #[n(2)] initiator: Tag,
        /// The recipient's identifying information.
        #[n(3)] recipient: Tag,
        /// The invitation data.
        #[n(4)] data_type: Tag
    },
    /// An invite acceptance.
    #[n(2)] Accept {
        /// The recipient's public key type tag.
        #[n(1)] identity: Tag
    },
}

/// The actual invitation data.
#[derive(Debug, Encode, Decode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Invitation<P, A, B, D> {
    /// The initiator's identity key.
    #[n(1)] initiator_id: P,
    /// Information about the initiator.
    ///
    /// The recipient uses it to identify the initiator unless the recipient is
    /// expected to have the initiator's identity key.
    #[n(2)] initiator_info: A,
    /// Information about the recipient.
    ///
    /// Contains data that the initiator used to identify the recipient.
    #[n(3)] recipient_info: B,
    /// Custom data attached to an invitation.
    #[n(4)] data: D
}

/// When accepting an invitation, an acceptance value will be returned.
#[derive(Debug, Encode, Decode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Acceptance<P> {
    /// The recipient's identity key.
    #[n(1)] recipient_id: P,
    /// The original invitation this acceptance applies to.
    #[n(2)] envelope: Envelope
}

/// A way to tag data so it can be analysed at runtime.
#[derive(Debug, Clone, Copy, Encode, Decode, PartialEq, Eq)]
#[cbor(transparent)]
pub struct Tag(#[n(0)] pub u32);

/// A cryptographic signature.
#[derive(Debug, Encode, Decode, PartialEq, Eq)]
#[cbor(transparent)]
pub struct Signature {
    #[cbor(n(0), with = "minicbor::bytes")]
    bytes: Vec<u8>,
}

impl Signature {
    pub fn new<V: Into<Vec<u8>>>(bytes: V) -> Self {
        Signature {
            bytes: bytes.into(),
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.bytes
    }
}

impl Envelope {
    pub fn invite<P, A, B, D>(inv: &Invitation<P, A, B, D>) -> Result<Self, Error>
    where
        P: Meta + Encode<()> + Verifier,
        A: Meta + Encode<()>,
        B: Meta + Encode<()>,
        D: Meta + Encode<()>,
    {
        let hdr = Header::Invite {
            identity: P::TAG,
            initiator: A::TAG,
            recipient: B::TAG,
            data_type: D::TAG,
        };
        Ok(Envelope {
            data: {
                let mut e = Encoder::new(Vec::new());
                e.encode(&hdr)?;
                e.encode(inv)?;
                e.into_writer()
            },
            sign: Vec::new(),
        })
    }

    pub fn accept<P>(acc: &Acceptance<P>) -> Result<Self, Error>
    where
        P: Meta + Verifier + Encode<()>,
    {
        let hdr = Header::Accept { identity: P::TAG };
        Ok(Envelope {
            data: {
                let mut e = Encoder::new(Vec::new());
                e.encode(&hdr)?;
                e.encode(acc)?;
                e.into_writer()
            },
            sign: Vec::new(),
        })
    }

    pub fn sign<T: Signer>(&mut self, s: T) -> Result<(), Error> {
        self.sign.push(s.sign(&self.data)?);
        Ok(())
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn signatures(&self) -> &[Signature] {
        &self.sign
    }

    /// Read the data and return the header as well as
    pub fn read_data(&self) -> Result<(Header, &[u8]), Error> {
        let mut d = Decoder::new(&self.data);
        let hdr = d.decode()?;
        Ok((hdr, &d.input()[d.position()..]))
    }
}

impl<P, A, B, D> Invitation<P, A, B, D>
where
    P: Meta + Encode<()> + Verifier,
    A: Meta + Encode<()>,
    B: Meta + Encode<()>,
{
    pub fn new(id: P, initiator_info: A, recipient_info: B, data: D) -> Self {
        Invitation {
            initiator_id: id,
            initiator_info,
            recipient_info,
            data,
        }
    }

    pub fn initiator(&self) -> &P {
        &self.initiator_id
    }

    pub fn initiator_info(&self) -> &A {
        &self.initiator_info
    }

    pub fn recipient_info(&self) -> &B {
        &self.recipient_info
    }

    pub fn data(&self) -> &D {
        &self.data
    }
}

impl<P> Acceptance<P>
where
    P: Meta + Verifier + Encode<()>,
{
    pub fn new(id: P, env: Envelope) -> Self {
        Acceptance {
            recipient_id: id,
            envelope: env,
        }
    }

    pub fn recipient(&self) -> &P {
        &self.recipient_id
    }

    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }
}

impl Header {
    pub fn is_accept(&self) -> bool {
        matches!(self, Header::Accept { .. })
    }

    pub fn is_invite(&self) -> bool {
        matches!(self, Header::Invite { .. })
    }

    pub fn identity(&self) -> Tag {
        match self {
            Header::Invite { identity, .. } => *identity,
            Header::Accept { identity, .. } => *identity,
        }
    }

    pub fn initiator(&self) -> Option<Tag> {
        if let Header::Invite { initiator, .. } = self {
            return Some(*initiator);
        }
        None
    }

    pub fn recipient(&self) -> Option<Tag> {
        if let Header::Invite { recipient, .. } = self {
            return Some(*recipient);
        }
        None
    }

    pub fn data(&self) -> Option<Tag> {
        if let Header::Invite { data_type, .. } = self {
            return Some(*data_type);
        }
        None
    }
}

/// A type that can sign data.
pub trait Signer {
    /// Calculate the signature of the given data.
    fn sign(&self, data: &[u8]) -> Result<Signature, Error>;
}

impl<T: Signer> Signer for &T {
    fn sign(&self, data: &[u8]) -> Result<Signature, Error> {
        (**self).sign(data)
    }
}

/// A type that can verify signatures.
pub trait Verifier {
    /// Is the signature valid?
    fn is_valid(&self, data: &[u8], sig: &Signature) -> bool;
}

impl<P: Verifier> Verifier for &P {
    fn is_valid(&self, data: &[u8], sig: &Signature) -> bool {
        (**self).is_valid(data, sig)
    }
}
