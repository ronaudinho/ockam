use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use minicbor::Decoder;

use ockam::authenticated_storage::AuthenticatedStorage;
use ockam::remote::RemoteForwarder;
use ockam::{Result, Route, Address};
use ockam_core::AsyncTryClone;
use ockam_core::api::{Response, Status, Id};
use ockam_identity::{IdentityIdentifier, TrustMultiIdentifiersPolicy};
use ockam_multiaddr::{MultiAddr, Protocol};
use ockam_multiaddr::proto::{DnsAddr, Ip4, Ip6, Tcp, Service};
use ockam_node::Context;
use ockam_node::tokio::time::timeout;
use ockam_vault::Vault;
use ockam_identity::Identity;

use crate::error::ApiError;
use crate::multiaddr_to_route;
use crate::nodes::models::forwarder::{CreateForwarder, ForwarderInfo};
use crate::nodes::models::secure_channel::CredentialExchangeMode;
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
                let ident = Arc::new(self.identity()?.async_try_clone().await?);
                let store = Arc::new(self.authenticated_storage.async_try_clone().await?);
                let addr = create_sec_chan(&ident, store.clone(), &req.address, &auth, req.mode).await?;
                let rote = Route::from(addr.clone());
                let alas = alias.to_string();
                let fwdr = if req.at_rust_node {
                    RemoteForwarder::create_static_without_heartbeats(ctx, rote, alas).await
                } else {
                    let fwdr = RemoteForwarder::create_static(ctx, rote, alas).await;
                    if fwdr.is_ok() {
                        let ctx = Arc::new(ctx.async_try_clone().await?);
                        let ses = Session::new(addr);
                        self.monitor(ses, ctx, ident, store, req.address, alias.to_string(), auth, req.mode).await?
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

    async fn monitor<S: AuthenticatedStorage>(
        &mut self,
        mut session: Session,
        ctx: Arc<Context>,
        ident: Arc<Identity<Vault>>,
        store: Arc<S>,
        addr: MultiAddr,
        alas: String,
        auth: Arc<HashMap<MultiAddr, IdentityIdentifier>>,
        mode: CredentialExchangeMode
    ) -> Result<()> {
        session.set_replacement(move || {
            let ctx = ctx.clone();
            let addr = addr.clone();
            let ident = ident.clone();
            let store = store.clone();
            let alas = alas.clone();
            let auth = auth.clone();
            Box::pin(async move {
                debug! {
                    target: "ockam_api::session",
                    addr = %addr,
                    "creating new remote forwarder"
                }
                let f = async {
                    let a = create_sec_chan(&ident, store.clone(), &addr, &auth, mode).await?;
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

async fn create_sec_chan<S: AuthenticatedStorage>(
    ident: &Identity<Vault>,
    store: Arc<S>,
    addr: &MultiAddr,
    authorised: &HashMap<MultiAddr, IdentityIdentifier>,
    mode: CredentialExchangeMode
) -> Result<Address> {
    let mut protos = addr.iter();
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
    let addr = MultiAddr::default().try_with(addr.iter().take(3)).map_err(map_multiaddr_err)?;
    let policy = authorised.get(&addr)
        .map(|i| TrustMultiIdentifiersPolicy::new(vec![i.clone()]))
        .ok_or_else(|| ApiError::generic("no authorisied identifier for address"))?;
    let route = multiaddr_to_route(&addr).ok_or_else(|| {
        ApiError::generic("invalid multiaddr")
    })?;
    ident.create_secure_channel(route, policy, &*store).await
}
