pub mod types;

use crate::signer::{self, types::Signed};
use crate::util::response;
use crate::{assert_request_match, assert_response_match};
use crate::{Error, Method, Request, RequestBuilder, Response, Status, Timestamp};
use core::fmt;
use minicbor::{Decoder, Encode};
use ockam_core::errcode::{Kind, Origin};
use ockam_core::{self, Address, Result, Route, Routed, Worker};
use ockam_identity::authenticated_storage::AuthenticatedStorage;
use ockam_identity::{IdentityIdentifier, IdentitySecureChannelLocalInfo};
use ockam_node::Context;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use serde_json as json;
use tracing::{trace, warn};
use types::{CredentialRequest, MemberCredential};
use url::Url;

// storage scope
const OAUTH2: &str = "oauth2";

#[derive(Debug)]
pub struct Server<S> {
    store: S,
    signer: signer::Client,
    client: reqwest::Client,
    url: Url,
}

#[ockam_core::worker]
impl<S: AuthenticatedStorage> Worker for Server<S> {
    type Context = Context;
    type Message = Vec<u8>;

    async fn handle_message(&mut self, c: &mut Context, m: Routed<Self::Message>) -> Result<()> {
        let i = IdentitySecureChannelLocalInfo::find_info(m.local_message())?;
        let r = self.on_request(i.their_identity_id(), m.as_body()).await?;
        c.send(m.return_route(), r).await
    }
}

impl<S: AuthenticatedStorage> Server<S> {
    pub fn new(store: S, signer: signer::Client, base: Url) -> Self {
        Server {
            store,
            signer,
            url: base,
            client: reqwest::Client::new(),
        }
    }

    async fn on_request(&mut self, from: &IdentityIdentifier, data: &[u8]) -> Result<Vec<u8>> {
        let mut dec = Decoder::new(data);
        let req: Request = dec.decode()?;

        trace! {
            target: "ockam_api::authenticator::oauth2::server",
            from   = %from,
            id     = %req.id(),
            method = ?req.method(),
            path   = %req.path(),
            body   = %req.has_body(),
            "request"
        }

        let res = match req.method() {
            Some(Method::Post) => match req.path_segments::<2>().as_slice() {
                ["register"] => {
                    let crq: CredentialRequest = dec.decode()?;
                    match self.fetch_user_profile(crq.access_token()).await {
                        Ok(json) => {
                            let now = Timestamp::now().ok_or_else(invalid_sys_time)?;
                            let crd = {
                                let mut mc = MemberCredential::new(now, from.into());
                                if let Some(e) = json.get("email").and_then(|e| e.as_str()) {
                                    let v = json
                                        .get("email_verified")
                                        .and_then(|b| b.as_bool())
                                        .unwrap_or(false);
                                    mc = mc.with_email(e, v)
                                }
                                mc
                            };
                            let sig = self.signer.sign(&crd).await?;
                            let vec = minicbor::to_vec(&sig)?;
                            self.store
                                .set(from.key_id(), OAUTH2.to_string(), vec)
                                .await?;
                            Response::ok(req.id()).body(&sig).to_vec()?
                        }
                        Err(err) => {
                            warn! {
                                from   = %from,
                                id     = %req.id(),
                                method = ?req.method(),
                                path   = %req.path(),
                                url    = %self.url,
                                "failed to fetch user profile"
                            }
                            if err.code().kind == Kind::Invalid {
                                Response::unauthorized(req.id()).to_vec()?
                            } else {
                                Response::internal_error(req.id()).to_vec()?
                            }
                        }
                    }
                }
                _ => response::unknown_path(&req).to_vec()?,
            },
            Some(Method::Get) => match req.path_segments::<3>().as_slice() {
                ["member", id] => {
                    if let Some(m) = self.store.get(id, OAUTH2).await? {
                        let s: Signed = minicbor::decode(&m)?;
                        Response::ok(req.id()).body(s).to_vec()?
                    } else {
                        Response::not_found(req.id()).to_vec()?
                    }
                }
                _ => response::unknown_path(&req).to_vec()?,
            },
            _ => response::invalid_method(&req).to_vec()?,
        };

        Ok(res)
    }

    async fn fetch_user_profile(&self, token: &str) -> Result<json::Value> {
        debug!(url = %self.url, "fetching user profile");
        let res = self
            .client
            .get(self.url.as_str())
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await
            .map_err(http_request_error)?;
        match res.status() {
            StatusCode::OK => {
                let body = res.bytes().await.map_err(http_request_error)?;
                let json = json::from_slice(&body).map_err(json_error)?;
                Ok(json)
            }
            StatusCode::UNAUTHORIZED => Err(ockam_core::Error::new(
                Origin::Application,
                Kind::Invalid,
                "unauthorized user profile access",
            )),
            other => {
                error!(url = %self.url, status = %other, "error response");
                Err(ockam_core::Error::new(
                    Origin::Application,
                    Kind::Io,
                    "failed to fetch user profile",
                ))
            }
        }
    }
}

fn invalid_sys_time() -> ockam_core::Error {
    ockam_core::Error::new(Origin::Node, Kind::Internal, "invalid system time")
}

fn http_request_error(e: reqwest::Error) -> ockam_core::Error {
    ockam_core::Error::new(Origin::Application, Kind::Io, e)
}

fn json_error(e: json::Error) -> ockam_core::Error {
    ockam_core::Error::new(Origin::Application, Kind::Io, e)
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

    pub async fn register(&mut self, req: &CredentialRequest<'_>) -> Result<Signed<'_>> {
        let req = Request::post("/register").body(req);
        self.buf = self
            .request("register", "oauth2_credential_request", &req)
            .await?;
        let mut d = Decoder::new(&self.buf);
        let res = response("register", &mut d)?;
        if res.status() == Some(Status::Ok) {
            assert_response_match("signer_signed", &self.buf);
            let a: Signed = d.decode()?;
            assert_response_match("oauth2_member_credential", a.data());
            let _: MemberCredential = minicbor::decode(a.data())?;
            Ok(a)
        } else {
            Err(error("register", &res, &mut d))
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
        assert_request_match(schema, &buf);
        trace! {
            target: "ockam_api::authenticator::oauth2::client",
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
        target: "ockam_api::authenticators::oauth2::client",
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
            target: "ockam_api::authenticators::oauth2::client",
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
