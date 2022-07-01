pub mod types;

use crate::{Timestamp, Error, Method, Request, Response, ResponseBuilder, Status};
use crate::signer::{self, types::Signed};
use minicbor::Decoder;
use ockam_core::errcode::{Kind, Origin};
use ockam_core::{self, Result, Routed, Worker};
use ockam_identity::{IdentitySecureChannelLocalInfo, IdentityIdentifier};
use ockam_identity::authenticated_storage::AuthenticatedStorage;
use ockam_node::Context;
use tracing::{trace, warn};
use types::{CredentialRequest, MemberCredential, Enroller, EnrollerInfo};

// storage scopes:
const ENROLLER: &str = "enroller";
const MEMBER: &str = "member";

#[derive(Debug)]
pub struct Server<S> {
    store: S,
    signer: signer::Client
}

#[ockam_core::worker]
impl<S: AuthenticatedStorage> Worker for Server<S> {
    type Context = Context;
    type Message = Vec<u8>;

    async fn handle_message(&mut self, c: &mut Context, m: Routed<Self::Message>) -> Result<()> {
        let r =
            if let Ok(i) = IdentitySecureChannelLocalInfo::find_info(m.local_message()) {
                self.on_authenticated_request(i.their_identity_id(), m.as_body()).await?
            } else {
                self.on_unauthenticated_request(m.as_body()).await?
            };
        c.send(m.return_route(), r).await
    }
}

impl<S: AuthenticatedStorage> Server<S> {
    pub fn new(store: S, signer: signer::Client) -> Self {
        Server { store, signer }
    }

    /// Configuration API to maintain the set of authorised enrollers.
    ///
    /// TODO: How to ensure this is only available locally or in an otherwise
    /// priviledged mode?
    async fn on_unauthenticated_request(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut dec = Decoder::new(data);
        let req: Request = dec.decode()?;

        debug! {
            target: "ockam_api::authenticator::direct::server",
            id     = %req.id(),
            method = ?req.method(),
            path   = %req.path(),
            body   = %req.has_body(),
            "unauthenticated request"
        }
        
        let res = match req.method() {
            Some(Method::Post) => match req.path_segments::<2>().as_slice() {
                ["register"] => {
                    let e: Enroller = dec.decode()?;
                    let n = Timestamp::now().ok_or_else(invalid_sys_time)?;
                    let i = EnrollerInfo::new(n);
                    let b = minicbor::to_vec(&i)?;
                    self.store.set(ENROLLER, e.enroller().to_string(), b).await?;
                    Response::ok(req.id()).to_vec()?
                }
                _ => unknown_path(&req).to_vec()?
            }
            Some(Method::Delete) => match req.path_segments::<3>().as_slice() {
                ["deregister", enroller] => {
                    self.store.del(ENROLLER, enroller).await?;
                    Response::ok(req.id()).to_vec()?
                }
                _ => unknown_path(&req).to_vec()?
            }
            _ => invalid_method(&req).to_vec()?
        };
        
        Ok(res)
    }

    /// Authentication requests from enrollers.
    async fn on_authenticated_request(&mut self, from: &IdentityIdentifier, data: &[u8]) -> Result<Vec<u8>> {
        let mut dec = Decoder::new(data);
        let req: Request = dec.decode()?;

        trace! {
            target: "ockam_api::authenticator::direct::server",
            from   = %from,
            id     = %req.id(),
            method = ?req.method(),
            path   = %req.path(),
            body   = %req.has_body(),
            "request"
        }
        
        let res = match req.method() {
            Some(Method::Post) => match req.path_segments::<2>().as_slice() {
                ["enroll"] => {
                    let crq: CredentialRequest = dec.decode()?;
                    if let Some(data) = self.store.get(ENROLLER, from.key_id()).await? {
                        minicbor::decode::<EnrollerInfo>(&data)?;
                        let now = Timestamp::now().ok_or_else(invalid_sys_time)?;
                        let crd = MemberCredential::new(now, crq.member());
                        let vec = minicbor::to_vec(&crd)?;
                        let sig = self.signer.sign(&vec).await?;
                        let vec = minicbor::to_vec(&sig)?;
                        self.store.set(MEMBER, crq.member().to_string(), vec).await?;
                        Response::ok(req.id()).body(&sig).to_vec()?
                    } else {
                        warn! {
                            target: "ockam_api::authenticator::direct::server",
                            enroller = %from,
                            id       = %req.id(),
                            method   = ?req.method(),
                            path     = %req.path(),
                            body     = %req.has_body(),
                            "unauthorised enroller"
                        }
                        let error = Error::new(req.path())
                            .with_method(Method::Post)
                            .with_message("unauthorized enroller");
                        Response::builder(req.id(), Status::Forbidden).body(error).to_vec()?
                    }
                }
                _ => unknown_path(&req).to_vec()?
            }
            Some(Method::Get) => match req.path_segments::<3>().as_slice() {
                ["member", id] => {
                    if let Some(m) = self.store.get(MEMBER, id).await? {
                        let s: Signed = minicbor::decode(&m)?;
                        Response::ok(req.id()).body(s).to_vec()?
                    } else {
                        Response::not_found(req.id()).to_vec()?
                    }
                }
                _ => unknown_path(&req).to_vec()?
            }
            _ => invalid_method(&req).to_vec()?
        };
        
        Ok(res)
    }
}

fn invalid_sys_time() -> ockam_core::Error {
    ockam_core::Error::new(Origin::Node, Kind::Internal, "invalid system time")
}

fn unknown_path<'a>(r: &'a Request) -> ResponseBuilder<Error<'a>> {
    let mut e = Error::new(r.path()).with_message("unknown path");
    if let Some(m) = r.method() {
        e = e.with_method(m)
    }
    Response::bad_request(r.id()).body(e)
}

fn invalid_method<'a>(r: &'a Request) -> ResponseBuilder<Error<'a>> {
    match r.method() {
        Some(m) => {
            let e = Error::new(r.path()).with_method(m);
            Response::builder(r.id(), Status::MethodNotAllowed).body(e)
        }
        None => {
            let e = Error::new(r.path()).with_message("unknown method");
            Response::not_implemented(r.id()).body(e)
        }
    }
}
