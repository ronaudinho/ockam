use crate::CowStr;
use minicbor::{Decode, Encode};
use ockam_core::compat::borrow::Cow;

#[cfg(feature = "tag")]
use ockam_core::TypeTag;

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct SetupAuthenticators<'a> {
    #[cfg(feature = "tag")]
    #[n(0)] tag: TypeTag<9750358>,
    #[n(1)] direct: Option<bool>,
    #[n(2)] direct_admin: Option<bool>,
    #[b(3)] oauth2: Option<Oauth2Config<'a>>
}

impl<'a> SetupAuthenticators<'a> {
    pub fn new() -> Self {
        SetupAuthenticators {
            #[cfg(feature = "tag")]
            tag: TypeTag,
            direct: None,
            direct_admin: None,
            oauth2: None,
        }
    }

    pub fn with_direct(mut self) -> Self {
        self.direct = Some(true);
        self
    }

    pub fn with_direct_admin(mut self) -> Self {
        self.direct_admin = Some(true);
        self
    }

    pub fn with_oauth2(mut self, cfg: Oauth2Config<'a>) -> Self {
        self.oauth2 = Some(cfg);
        self
    }

    pub fn is_direct(&self) -> bool {
        Some(true) == self.direct
    }

    pub fn is_direct_admin(&self) -> bool {
        Some(true) == self.direct_admin
    }

    pub fn oauth2(&self) -> Option<&Oauth2Config<'a>> {
        if let Some(c) = &self.oauth2 {
            return Some(c);
        }
        None
    }
}

#[derive(Debug, Decode, Encode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Oauth2Config<'a> {
    #[cfg(feature = "tag")]
    #[n(0)] tag: TypeTag<539172>,
    #[b(1)] url: CowStr<'a>,
}

impl<'a> Oauth2Config<'a> {
    pub fn new<S: Into<Cow<'a, str>>>(url: S) -> Self {
        Oauth2Config {
            #[cfg(feature = "tag")]
            tag: TypTag,
            url: CowStr(url.into()),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}
