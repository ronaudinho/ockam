use crate::{CowStr, Timestamp};
use minicbor::{Decode, Encode};
use ockam_core::compat::borrow::Cow;

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct CredentialRequest<'a> {
    #[cfg(feature = "tag")]
    #[n(0)] tag: TypeTag<7586022>,
    #[b(1)] tkn: CowStr<'a>
}

impl<'a> CredentialRequest<'a> {
    pub fn new<S: Into<Cow<'a, str>>>(token: S) -> Self {
        CredentialRequest {
            #[cfg(feature = "tag")]
            tag: TypeTag,
            tkn: CowStr(token.into())
        }
    }

    pub fn access_token(&self) -> &str {
        &self.tkn
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct MemberCredential<'a> {
    #[n(0)] issued_at: Timestamp,
    #[b(1)] member: CowStr<'a>,
    #[b(2)] profile: Option<CowStr<'a>>
}

impl<'a> MemberCredential<'a> {
    pub fn new<S: Into<Cow<'a, str>>>(t: Timestamp, m: S) -> Self {
        MemberCredential {
            issued_at: t,
            member: CowStr(m.into()),
            profile: None
        }
    }
    
    pub fn with_profile<P: Into<Cow<'a, str>>>(self, p: P) -> Self {
        MemberCredential {
            profile: Some(CowStr(p.into())),
            ..self
        }
    }

    pub fn member(&self) -> &str {
        &self.member
    }

    pub fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    pub fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }
}

