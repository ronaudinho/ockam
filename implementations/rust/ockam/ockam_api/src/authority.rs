pub mod types;

use crate::{assert_request_match, assert_response_match};
use crate::{Error, Method, Request, RequestBuilder, Response, Status};
use core::fmt;
use minicbor::{Decoder, Encode};
use ockam::authenticated_storage::AuthenticatedStorage;
use ockam_core::errcode::{Kind, Origin};
use ockam_core::{self, vault, Result, Address, Route, Routed, Worker};
use ockam_identity::{Identity, IdentityIdentifier, IdentitySecureChannelLocalInfo, IdentityVault};
use ockam_node::Context;
use tracing::{trace, warn};
use types::{CredentialRequest, Membership, Oauth2, Signature, Signed, Timestamp};
use url::Url;

pub struct Config<V: IdentityVault, S: AuthenticatedStorage> {
    id: Identity<V>,
    store: S,
    auth0: Option<Auth0Config>
}

impl<V: IdentityVault, S: AuthenticatedStorage> Config<V, S> {
    pub fn new(id: Identity<V>, s: S) -> Self {
        Config { id, store: s, auth0: None }
    }
    
    pub fn with_auth0(self, cfg: Auth0Config) -> Self {
        Config { auth0: Some(cfg), ..self }
    }
}

pub struct Auth0Config {
    url: Url,
}

impl Auth0Config {
    pub fn new(url: Url) -> Self {
        Auth0Config { url }
    }
}

pub struct Server<V: IdentityVault, S: AuthenticatedStorage> {
    config: Config<V, S>,
}

#[ockam_core::worker]
impl<V: IdentityVault, S: AuthenticatedStorage> Worker for Server<V, S> {
    type Context = Context;
    type Message = Vec<u8>;

    async fn handle_message(&mut self, ctx: &mut Context, msg: Routed<Self::Message>) -> Result<()> {
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
    
    async fn on_request(&mut self, they: &IdentityIdentifier, data: &[u8]) -> Result<Vec<u8>> {
        let mut dec = Decoder::new(data);
        let req: Request = dec.decode()?;

        debug! {
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
                    CredentialRequest::Oauth2 { data, signature } => {
                        if let Some(_cfg) = &self.config.auth0 {
                            self.verify(&data, &signature).await?;
                            let pubkey = self.resolve_key(signature.key_id()).await?;
                            let _tkn: Oauth2 = minicbor::decode(&data)?;
                            let attrs = "TODO: get user profile from auth0";
                            let now = Timestamp::now().ok_or_else(|| invalid_sys_time())?;
                            let cred = {
                                let m = Membership::new(now, signature.key_id(), pubkey)
                                    .with_attributes(attrs);
                                minicbor::to_vec(&m)?
                            };
                            let sig = self.config.id.create_signature(&cred).await?;
                            let this = self.config.id.identifier()?;
                            let body = Signed::new(&cred, Signature::new(this.key_id(), sig.as_ref()));
                            Response::ok(req.id()).body(body).to_vec()?
                        } else {
                            let error = Error::new(req.path())
                                .with_method(Method::Post)
                                .with_message("oauth2 is not configured");
                            Response::not_implemented(req.id()).body(error).to_vec()?
                        }
                    }
                    CredentialRequest::CreateSpace { data, signature } => {
                        self.verify(&data, &signature).await?;
                        todo!()
                    }
                    CredentialRequest::CreateProject { data, signature } => {
                        self.verify(&data, &signature).await?;
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

    async fn verify(&self, data: &[u8], sig: &Signature<'_>) -> Result<()> {
        let id = IdentityIdentifier::from_key_id(sig.key_id().into());
        let sg = vault::Signature::new(sig.signature().to_vec()); // TODO: avoid allocation
        if self.config.id.verify_signature(&sg, &id, data, &self.config.store).await? {
            Ok(())
        } else {
            Err(invalid_signature())
        }
    }

    async fn resolve_key(&self, key_id: &str) -> Result<vault::PublicKey> {
        let id = IdentityIdentifier::from_key_id(key_id.into());
        if let Some(id) = self.config.id.get_known_identity(&id, &self.config.store).await? {
            return id.get_root_public_key()
        }
        Err(unknown_identity(key_id))
    }
}

fn invalid_signature() -> ockam_core::Error {
   ockam_core::Error::new(Origin::Application, Kind::Invalid, "invalid signature")
}

fn unknown_identity(id: &str) -> ockam_core::Error {
   ockam_core::Error::new(Origin::Application, Kind::Invalid, format!("unknown identity {id}"))
}

fn invalid_sys_time() -> ockam_core::Error {
   ockam_core::Error::new(Origin::Node, Kind::Internal, "invalid system time")
}

pub struct Client {
    ctx: Context,
    route: Route,
    buf: Vec<u8>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("route", &self.route)
            .finish()
    }
}

impl Client {
    pub async fn new(r: Route, ctx: &Context) -> Result<Self> {
        let ctx = ctx.new_detached(Address::random_local()).await?;
        Ok(Client {
            ctx,
            route: r,
            buf: Vec::new(),
        })
    }

    pub async fn sign(&mut self, req: &CredentialRequest<'_>) -> Result<Signed<'_>> {
        let req = Request::post("/sign").body(req);
        self.buf = self.request("sign", "todo", &req).await?;
        let mut d = Decoder::new(&self.buf);
        let res = response("sign", &mut d)?;
        if res.status() == Some(Status::Ok) {
            // TODO: assert_response_match("todo", &self.buf);
            let a: Signed = d.decode()?;
            Ok(a)
        } else {
            Err(error("sign", &res, &mut d))
        }
    }

    /// Encode request header and body (if any) and send the package to the server.
    async fn request<T>(
        &mut self,
        label: &str,
        schema: impl Into<Option<&str>>,
        req: &RequestBuilder<'_, T>,
    ) -> Result<Vec<u8>>
    where
        T: Encode<()>,
    {
        let mut buf = Vec::new();
        req.encode(&mut buf)?;
        // TODO: assert_request_match(schema, &buf);
        trace! {
            target: "ockam_api::authority::client",
            id     = %req.header().id(),
            method = ?req.header().method(),
            path   = %req.header().path(),
            body   = %req.header().has_body(),
            "-> {label}"
        };
        let vec: Vec<u8> = self.ctx.send_and_receive(self.route.clone(), buf).await?;
        Ok(vec)
    }
}

/// Decode and log response header.
fn response(label: &str, dec: &mut Decoder<'_>) -> Result<Response> {
    let res: Response = dec.decode()?;
    trace! {
        target: "ockam_api::authority::client",
        re     = %res.re(),
        id     = %res.id(),
        status = ?res.status(),
        body   = %res.has_body(),
        "<- {label}"
    }
    Ok(res)
}

/// Decode, log and map response error to ockam_core error.
fn error(label: &str, res: &Response, dec: &mut Decoder<'_>) -> ockam_core::Error {
    if res.has_body() {
        let err = match dec.decode::<Error>() {
            Ok(e) => e,
            Err(e) => return e.into(),
        };
        warn! {
            target: "ockam_api::authority::client",
            id     = %res.id(),
            re     = %res.re(),
            status = ?res.status(),
            error  = ?err.message(),
            "<- {label}"
        }
        let msg = err.message().unwrap_or(label);
        ockam_core::Error::new(Origin::Application, Kind::Protocol, msg)
    } else {
        ockam_core::Error::new(Origin::Application, Kind::Protocol, label)
    }
}

