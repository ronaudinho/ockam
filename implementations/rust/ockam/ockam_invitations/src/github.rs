use crate::{ssh, Invitation, Meta, Tag, Verifier};
use minicbor::{Decode, Encode};

pub const GITHUB: Tag = Tag(1);

#[derive(Encode, Decode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct GitHub {
    #[n(1)] usr: String,
    #[n(2)] key: ssh::PubKey
}

impl Meta for GitHub {
    const TAG: Tag = GITHUB;
}

impl GitHub {
    pub fn new(name: String, key: ssh::PubKey) -> Self {
        GitHub { usr: name, key }
    }

    pub fn user(&self) -> &str {
        &self.usr
    }

    pub fn key(&self) -> &ssh::PubKey {
        &self.key
    }
}

pub fn invite<P, D>(a: P, g: GitHub, b: GitHub, d: D) -> Invitation<P, GitHub, GitHub, D>
where
    P: Meta + Encode<()> + Verifier,
{
    Invitation::new(a, g, b, d)
}
