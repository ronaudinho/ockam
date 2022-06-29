#[cfg(feature = "direct-authenticator")]
pub mod direct;

#[cfg(feature = "oauth2-authenticator")]
pub mod oauth2;