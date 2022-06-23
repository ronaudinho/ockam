mod types;

use crate::{Error, Method, Request, RequestBuilder, Response, Status};
use core::convert::Infallible;
use core::fmt;
use minicbor::{Decoder, Encode};
use ockam::authenticated_storage::AuthenticatedStorage;
use ockam_core::errcode::{Kind, Origin};
use ockam_core::{self, vault, Address, Route, Routed, Worker};
use ockam_identity::{Identity, IdentityIdentifier, IdentitySecureChannelLocalInfo, IdentityVault};
use ockam_node::Context;
use std::borrow::Cow;
use tracing::{trace, warn};
use types::{CredentialRequest, Membership, Oauth2, Signature, Timestamp};
use url::Url;

pub struct Config<V: IdentityVault, S: AuthenticatedStorage> {
    id: Identity<V>,
    store: S,
    auth0: Option<Auth0Config>
}

pub struct Auth0Config {
    url: Url,
}

pub struct Server<V: IdentityVault, S: AuthenticatedStorage> {
    config: Config<V, S>,
}

#[ockam_core::worker]
impl<V: IdentityVault, S: AuthenticatedStorage> Worker for Server<V, S> {
    type Context = Context;
    type Message = Vec<u8>;

    async fn handle_message(
        &mut self,
        ctx: &mut Context,
        msg: Routed<Self::Message>,
    ) -> ockam_core::Result<()> {
        let info = IdentitySecureChannelLocalInfo::find_info(msg.local_message())?;
        let they = info.their_identity_id();
        let res = self.on_request(they, msg.as_body()).await?;
        ctx.send(msg.return_route(), res).await
    }
}

impl<V: IdentityVault, S: AuthenticatedStorage> Server<V, S> {
    pub fn new(c: Config<V, S>) -> Self {
        Server { config: c }
    }
    
    async fn on_request(&mut self, they: &IdentityIdentifier, data: &[u8]) -> Result<Vec<u8>, AuthorityError> {
        let mut dec = Decoder::new(data);
        let req: Request = dec.decode()?;

        trace! {
            target: "ockam_api::authority::server",
            from   = %they,
            id     = %req.id(),
            method = ?req.method(),
            path   = %req.path(),
            body   = %req.has_body(),
            "request"
        }
        
        let res = match req.method() {
            Some(Method::Post) => match req.path_segments::<2>().as_slice() {
                ["sign"] => match dec.decode()? {
                    CredentialRequest::Oauth2 { dat, sig } => {
                        if let Some(_cfg) = &self.config.auth0 {
                            self.verify(&dat, &sig).await?;
                            let pubkey = self.resolve_key(sig.key_id()).await?;
                            let _tkn: Oauth2 = minicbor::decode(&dat)?;
                            let attrs = "TODO: get user profile from auth0";
                            let now = Timestamp::now()
                                .ok_or_else(|| AuthorityError::invalid_sys_time())?;
                            let cred = {
                                let m = Membership::new(now, sig.key_id(), Cow::Borrowed(&pubkey))
                                    .with_attributes(attrs);
                                minicbor::to_vec(&m)?
                            };
                            Response::ok(req.id()).body(cred).to_vec()?
                        } else {
                            let error = Error::new(req.path())
                                .with_method(Method::Post)
                                .with_message("oauth2 is not configured");
                            Response::not_implemented(req.id()).body(error).to_vec()?
                        }
                    }
                    CredentialRequest::CreateSpace { dat, sig } => {
                        self.verify(&dat, &sig).await?;
                        todo!()
                    }
                    CredentialRequest::CreateProject { dat, sig } => {
                        self.verify(&dat, &sig).await?;
                        todo!()
                    }
                }
                _ => {
                    let error = Error::new(req.path())
                        .with_method(Method::Post)
                        .with_message("unknown path");
                    Response::bad_request(req.id()).body(error).to_vec()?
                }
            },
            _ => todo!()
        };
        
        Ok(res)
    }

    async fn verify(&self, data: &[u8], sig: &Signature<'_>) -> Result<(), AuthorityError> {
        let id = sig.key_id().try_into().map_err(AuthorityError::invalid_key_id)?;
        let sg = vault::Signature::new(sig.signature().to_vec()); // TODO: avoid allocation
        let ok = self.config.id.verify_signature(&sg, &id, data, &self.config.store)
            .await
            .map_err(AuthorityError::other)?;
        if ok {
            Ok(())
        } else {
            Err(AuthorityError::invalid_signature())
        }
    }

    async fn resolve_key(&self, key_id: &str) -> Result<vault::PublicKey, AuthorityError> {
        let id = key_id.try_into().map_err(AuthorityError::invalid_key_id)?;
        if let Some(id) = self.config.id.get_known_identity(&id, &self.config.store)
            .await
            .map_err(AuthorityError::other)?
        {
            return id.get_root_public_key().map_err(AuthorityError::other)
        }
        Err(AuthorityError::unknown_identity(key_id))
    }
}

#[derive(Debug)]
pub struct AuthorityError(ErrorImpl);

impl AuthorityError {
    fn invalid_signature() -> Self {
        AuthorityError(ErrorImpl::InvalidSignature)
    }

    fn invalid_key_id(e: ockam_core::Error) -> Self {
        AuthorityError(ErrorImpl::InvalidKeyId(e))
    }
    
    fn invalid_sys_time() -> Self {
        AuthorityError(ErrorImpl::InvalidSystemTime)
    }
    
    fn unknown_identity(key_id: &str) -> Self {
        AuthorityError(ErrorImpl::UnknownId(key_id.to_string()))
    }

    fn other(e: ockam_core::Error) -> Self {
        AuthorityError(ErrorImpl::Other(e))
    }
}

#[derive(Debug)]
enum ErrorImpl {
    Decode(minicbor::decode::Error),
    Encode(minicbor::encode::Error<Infallible>),
    InvalidKeyId(ockam_core::Error),
    Other(ockam_core::Error),
    InvalidSignature,
    InvalidSystemTime,
    UnknownId(String)
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ErrorImpl::Encode(e) => e.fmt(f),
            ErrorImpl::Decode(e) => e.fmt(f),
            ErrorImpl::InvalidKeyId(e) => e.fmt(f),
            ErrorImpl::Other(e) => e.fmt(f),
            ErrorImpl::InvalidSignature => f.write_str("invalid signature"),
            ErrorImpl::InvalidSystemTime => f.write_str("invalid system time"),
            ErrorImpl::UnknownId(id) => write!(f, "unknown key id: {id}")
        }
    }
}

impl std::error::Error for AuthorityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            ErrorImpl::Decode(e) => Some(e),
            ErrorImpl::Encode(e) => Some(e),
            ErrorImpl::InvalidKeyId(e) => Some(e),
            ErrorImpl::Other(e) => Some(e),
            ErrorImpl::InvalidSignature => None,
            ErrorImpl::InvalidSystemTime => None,
            ErrorImpl::UnknownId(_) => None
        }
    }
}

impl From<minicbor::decode::Error> for AuthorityError {
    fn from(e: minicbor::decode::Error) -> Self {
        AuthorityError(ErrorImpl::Decode(e))
    }
}

impl From<minicbor::encode::Error<Infallible>> for AuthorityError {
    fn from(e: minicbor::encode::Error<Infallible>) -> Self {
        AuthorityError(ErrorImpl::Encode(e))
    }
}

impl From<AuthorityError> for ockam_core::Error {
    fn from(e: AuthorityError) -> Self {
        ockam_core::Error::new(Origin::Application, Kind::Invalid, e)
    }
}

impl From<Infallible> for AuthorityError {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}
