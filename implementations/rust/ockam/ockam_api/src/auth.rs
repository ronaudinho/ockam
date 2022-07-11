pub mod types;

use crate::util::response;
use crate::{assert_request_match, assert_response_match};
use crate::{Error, Method, Request, RequestBuilder, Response, Status};
use core::fmt;
use minicbor::{Decoder, Encode};
use ockam_core::errcode::{Kind, Origin};
use ockam_core::{self, Address, Result, Route, Routed, Worker};
use ockam_identity::authenticated_storage::AuthenticatedStorage;
use ockam_node::Context;
use tracing::{trace, warn};
use types::Attribute;

/// Auth API server.
#[derive(Debug)]
pub struct Server<S> {
    store: S,
}

#[ockam_core::worker]
impl<S: AuthenticatedStorage> Worker for Server<S> {
    type Context = Context;
    type Message = Vec<u8>;

    async fn handle_message(&mut self, c: &mut Context, m: Routed<Self::Message>) -> Result<()> {
        let r = self.on_request(m.as_body()).await?;
        c.send(m.return_route(), r).await
    }
}

impl<S: AuthenticatedStorage> Server<S> {
    pub fn new(s: S) -> Self {
        Server { store: s }
    }

    async fn on_request(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut dec = Decoder::new(data);
        let req: Request = dec.decode()?;

        trace! {
            target: "ockam_api::auth::server",
            id     = %req.id(),
            method = ?req.method(),
            path   = %req.path(),
            body   = %req.has_body(),
            "request"
        }

        let res = match req.method() {
            Some(Method::Get) => match req.path_segments::<5>().as_slice() {
                ["authenticated", id, "attribute", key] => {
                    if let Some(a) = self.store.get(id, key).await? {
                        Response::ok(req.id()).body(Attribute::new(&a)).to_vec()?
                    } else {
                        Response::not_found(req.id()).to_vec()?
                    }
                }
                _ => response::unknown_path(&req).to_vec()?,
            },
            Some(Method::Delete) => match req.path_segments::<5>().as_slice() {
                ["authenticated", id, "attribute", key] => {
                    self.store.del(id, key).await?;
                    Response::ok(req.id()).to_vec()?
                }
                _ => response::unknown_path(&req).to_vec()?,
            },
            _ => response::invalid_method(&req).to_vec()?,
        };

        Ok(res)
    }
}

/// Auth API client.
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
    pub async fn new(r: Route, ctx: &Context) -> ockam_core::Result<Self> {
        let ctx = ctx.new_detached(Address::random_local()).await?;
        Ok(Client {
            ctx,
            route: r,
            buf: Vec::new(),
        })
    }

    pub async fn get(&mut self, id: &str, attr: &str) -> Result<Option<&[u8]>> {
        let req = Request::get(format!("/authenticated/{id}/attribute/{attr}"));
        self.buf = self.request("get attribute", None, &req).await?;
        let mut d = Decoder::new(&self.buf);
        let res = response("get attribute", &mut d)?;
        match res.status() {
            Some(Status::Ok) => {
                assert_response_match("attribute", &self.buf);
                let a: Attribute = d.decode()?;
                Ok(Some(a.value()))
            }
            Some(Status::NotFound) => Ok(None),
            _ => Err(error("get attribute", &res, &mut d)),
        }
    }

    pub async fn del(&mut self, id: &str, attr: &str) -> Result<()> {
        let req = Request::delete(format!("/authenticated/{id}/attribute/{attr}"));
        self.buf = self.request("del attribute", None, &req).await?;
        assert_response_match(None, &self.buf);
        let mut d = Decoder::new(&self.buf);
        let res = response("del attribute", &mut d)?;
        if res.status() == Some(Status::Ok) {
            Ok(())
        } else {
            Err(error("del attribute", &res, &mut d))
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
            target: "ockam_api::auth::client",
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
        target: "ockam_api::auth::client",
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
            target: "ockam_api::auth::client",
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
