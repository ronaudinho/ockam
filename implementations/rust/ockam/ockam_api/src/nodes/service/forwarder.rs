use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use minicbor::Decoder;

use ockam::remote::RemoteForwarder;
use ockam::{Result, Route, Address};
use ockam_core::AsyncTryClone;
use ockam_core::api::{Error, Response, Status, Id, Request};
use ockam_identity::IdentityIdentifier;
use ockam_multiaddr::{MultiAddr, Protocol};
use ockam_multiaddr::proto::{DnsAddr, Ip4, Ip6, Tcp, Service};
use ockam_node::Context;
use ockam_node::tokio::time::timeout;

use crate::error::ApiError;
use crate::multiaddr_to_route;
use crate::nodes::models::forwarder::{CreateForwarder, ForwarderInfo};
use crate::nodes::models::secure_channel::{CredentialExchangeMode, CreateSecureChannelRequest, CreateSecureChannelResponse, DeleteSecureChannelRequest};
use crate::nodes::service::map_multiaddr_err;
use crate::nodes::NodeManager;
use crate::session::Session;

impl NodeManager {
    pub(super) async fn create_forwarder(
        &mut self,
        ctx: &mut Context,
        rid: Id,
        dec: &mut Decoder<'_>,
    ) -> Result<Vec<u8>> {
        let req: CreateForwarder = dec.decode()?;

        debug!(addr = %req.address, alias = ?req.alias, "Handling CreateForwarder request");

        let forwarder = match req.alias {
            Some(alias) => {
                let auth = Arc::new(req.identities);
                let addr = {
                    let a = map_addr(&req.address)?;
                    let r = multiaddr_to_route(&a).ok_or_else(|| {
                        ApiError::generic("invalid multiaddr")
                    })?;
                    let v = auth.get(&a).map(|i| vec![i.clone()]);
                    self.create_secure_channel_impl(r, v, req.mode).await?
                };
                let rote = Route::from(addr.clone());
                let alas = alias.to_string();
                let fwdr = if req.at_rust_node {
                    RemoteForwarder::create_static_without_heartbeats(ctx, rote, alas).await
                } else {
                    let fwdr = RemoteForwarder::create_static(ctx, rote, alas).await;
                    if fwdr.is_ok() {
                        let ctx = Arc::new(ctx.async_try_clone().await?);
                        let ses = Session::new(addr);
                        self.monitor(ses, ctx, req.address, alias.to_string(), auth, req.mode).await?
                    }
                    fwdr
                };
                fwdr
            }
            None => {
                let r = multiaddr_to_route(&req.address).ok_or_else(|| {
                    ApiError::generic("invalid multiaddress")
                })?;
                RemoteForwarder::create(ctx, r).await
            }
        };

        match forwarder {
            Ok(info) => {
                let b = ForwarderInfo::from(info);
                debug!(
                    forwarding_route = %b.forwarding_route(),
                    remote_address = %b.remote_address(),
                    "CreateForwarder request processed, sending back response"
                );
                Ok(Response::ok(rid).body(b).to_vec()?)
            }
            Err(err) => {
                error!(?err, "Failed to create forwarder");
                Ok(Response::builder(rid, Status::InternalServerError)
                    .body(err.to_string())
                    .to_vec()?)
            }
        }
    }

    async fn monitor(
        &mut self,
        mut session: Session,
        ctx: Arc<Context>,
        addr: MultiAddr,
        alas: String,
        auth: Arc<HashMap<MultiAddr, IdentityIdentifier>>,
        mode: CredentialExchangeMode
    ) -> Result<()> {
        let manager = self.address.clone();
        session.set_replacement(move |prev| {
            let ctx = ctx.clone();
            let addr = addr.clone();
            let alas = alas.clone();
            let auth = auth.clone();
            let magr = manager.clone();
            Box::pin(async move {
                debug! {
                    target: "ockam_api::session",
                    addr = %addr,
                    "creating new remote forwarder"
                }
                let f = async {
                    let a = replace_sec_chan(&ctx, &magr, prev, &addr, &auth, mode).await?;
                    RemoteForwarder::create_static(&ctx, Route::from(a.clone()), alas).await?;
                    Ok(a)
                };
                match timeout(Duration::from_secs(7), f).await {
                    Err(_) => {
                        warn! {
                            target: "ockam_api::session",
                            "timeout creating new remote forwarder"
                        }
                        Err(ApiError::generic("timeout"))
                    }
                    Ok(Err(e)) => {
                        warn! {
                            target: "ockam_api::session",
                            err = %e,
                            "error creating new remote forwarder"
                        }
                        Err(e)
                    }
                    Ok(Ok(a)) => Ok(a)
                }
            })
        });
        self.sessions.lock().unwrap().add(session);
        Ok(())
    }
}

fn map_addr(input: &MultiAddr) -> Result<MultiAddr> {
    let mut protos = input.iter();
    if !matches!(protos.next().map(|p| p.code()), Some(DnsAddr::CODE | Ip4::CODE | Ip6::CODE)) {
        return Err(ApiError::generic("invalid forwarder address (expecting ip address or dns name)"))
    }
    if !matches!(protos.next().map(|p| p.code()), Some(Tcp::CODE)) {
        return Err(ApiError::generic("invalid forwarder address (expecting tcp port)"))
    }
    if !matches!(protos.next().map(|p| p.code()), Some(Service::CODE)) {
        return Err(ApiError::generic("invalid forwarder address (expecting service name)"))
    }
    if let Some(p) = protos.next() {
        return Err(ApiError::generic("invalid forwarder address (unexpected additional proto)"))
    }
    MultiAddr::default().try_with(input.iter().take(3)).map_err(map_multiaddr_err)
}

async fn replace_sec_chan(
    ctx: &Context,
    manager: &Address,
    prev: Address,
    addr: &MultiAddr,
    authorised: &HashMap<MultiAddr, IdentityIdentifier>,
    mode: CredentialExchangeMode
) -> Result<Address> {
    debug! {
        target: "ockam_api::session",
        prev = %prev,
        addr = %addr,
        "recreating secure channel"
    }
    let req = DeleteSecureChannelRequest::new(&prev);
    let req = Request::delete("/node/secure_channel").body(req).to_vec()?;
    let vec: Vec<u8> = ctx.send_and_receive(manager.clone(), req).await?;
    let mut d = Decoder::new(&vec);
    let res: Response = d.decode()?;
    if res.status() != Some(Status::Ok) {
        if res.has_body() {
            let e: Error = d.decode()?; // TODO
        }
    }
    let ids = authorised.get(addr).map(|i| vec![i.clone()]);
    let req = CreateSecureChannelRequest::new(addr, ids, mode);
    let req = Request::post("/node/secure_channel").body(req).to_vec()?;
    let vec: Vec<u8> = ctx.send_and_receive(manager.clone(), req).await?;
    let mut d = Decoder::new(&vec);
    let res: Response = d.decode()?;
    if res.status() != Some(Status::Ok) {
        if res.has_body() {
            let e: Error = d.decode()?; // TODO
        }
        return Err(ApiError::generic("error creating secure channel"))
    }
    let res: CreateSecureChannelResponse = d.decode()?;
    let mad = res.addr()?;
    if let Some(p) = mad.first() {
        if let Some(p) = p.cast::<Service>() {
            return Ok(Address::from_string(&*p))
        }
    }
    Err(ApiError::generic("invalid response address"))
}
