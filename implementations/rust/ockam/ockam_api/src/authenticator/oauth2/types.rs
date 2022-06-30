use crate::{CowStr, Timestamp};
use crate::authenticator::IdentityId;
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
    #[b(1)] member: IdentityId<'a>,
    #[b(2)] email: Option<CowStr<'a>>,
    #[b(3)] email_verified: Option<bool>
}

impl<'a> MemberCredential<'a> {
    pub fn new(t: Timestamp, member: IdentityId<'a>) -> Self {
        MemberCredential {
            issued_at: t,
            member,
            email: None,
            email_verified: None
        }
    }
    
    pub fn with_email<E: Into<Cow<'a, str>>>(mut self, email: E, is_verified: bool) -> Self {
        self.email = Some(CowStr(email.into()));
        self.email_verified = Some(is_verified);
        self
    }

    pub fn member(&self) -> &IdentityId {
        &self.member
    }

    pub fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
    
    pub fn is_email_verified(&self) -> Option<bool> {
        self.email_verified
    }
}

