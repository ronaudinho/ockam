pub mod types;

use crate::{assert_request_match, assert_response_match};
use crate::{Error, Method, Request, RequestBuilder, Response, Status};
use core::fmt;
use minicbor::{Decoder, Encode};
use ockam_core::errcode::{Kind, Origin};
use ockam_core::{self, Result, Address, Route, Routed, Worker};
use ockam_identity::{Identity, IdentityVault};
use ockam_node::Context;
use tracing::{trace, warn};
use types::{Signature, Signed};

/// A signer server signs arbitrary data handed to it.
pub struct Server<V: IdentityVault> {
    id: Identity<V>
}

impl<V: IdentityVault> fmt::Debug for Server<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server").finish()
    }
}

#[ockam_core::worker]
impl<V: IdentityVault> Worker for Server<V> {
    type Context = Context;
    type Message = Vec<u8>;

    async fn handle_message(&mut self, c: &mut Context, m: Routed<Self::Message>) -> Result<()> {
        let r = self.on_request(m.as_body()).await?;
        c.send(m.return_route(), r).await
    }
}

impl<V: IdentityVault> Server<V> {
    pub fn new(id: Identity<V>) -> Self {
        Server { id }
    }

    async fn on_request(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut dec = Decoder::new(data);
        let req: Request = dec.decode()?;

        trace! {
            target: "ockam_api::signer::server",
            id     = %req.id(),
            method = ?req.method(),
            path   = %req.path(),
            body   = %req.has_body(),
            "request"
        }
        
        let res = match req.method() {
            Some(Method::Post) => match req.path_segments::<2>().as_slice() {
                ["sign"] => {
                    let dat = &dec.input()[dec.position() ..];
                    let kid = self.id.identifier()?;
                    let sig = self.id.create_signature(dat).await?;
                    let bdy = Signed::new(dat, Signature::new(kid.key_id(), sig.as_ref()));
                    Response::ok(req.id()).body(bdy).to_vec()?
                }
                _ => {
                    let error = Error::new(req.path())
                        .with_method(Method::Post)
                        .with_message("unknown path");
                    Response::bad_request(req.id()).body(error).to_vec()?
                }
            }
            Some(m) => {
                let error = Error::new(req.path()).with_method(m);
                Response::builder(req.id(), Status::MethodNotAllowed)
                    .body(error)
                    .to_vec()?
            }
            None => {
                let error = Error::new(req.path()).with_message("unknown method");
                Response::not_implemented(req.id())
                    .body(error)
                    .to_vec()?
            }
        };
        
        Ok(res)
    }
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

    /// Have some data signed by the signer.
    pub async fn sign(&mut self, data: &[u8]) -> Result<Signed<'_>> {
        let req = Request::post("/sign").body(data);
        self.buf = self.request("sign", None, &req).await?;
        assert_response_match("signer_signed", &self.buf);
        let mut d = Decoder::new(&self.buf);
        let res = response("sign", &mut d)?;
        if res.status() == Some(Status::Ok) {
            let s: Signed = d.decode()?;
            Ok(s)
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
        assert_request_match(schema, &buf);
        trace! {
            target: "ockam_api::signer::client",
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
        target: "ockam_api::signer::client",
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
            target: "ockam_api::signer::client",
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

