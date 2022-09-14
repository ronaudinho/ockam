use std::sync::Arc;

use minicbor::Decoder;

use ockam::remote::RemoteForwarder;
use ockam::{Result, Route, TCP};
use ockam_core::AsyncTryClone;
use ockam_core::api::{Request, Response, Status};
use ockam_multiaddr::MultiAddr;
use ockam_node::Context;

use crate::error::ApiError;
use crate::nodes::models::forwarder::{CreateForwarder, ForwarderInfo};
use crate::nodes::service::map_multiaddr_err;
use crate::nodes::NodeManager;
use crate::session::{Session, Mode};

impl NodeManager {
    pub(super) async fn create_forwarder(
        &mut self,
        ctx: &mut Context,
        req: &Request<'_>,
        dec: &mut Decoder<'_>,
    ) -> Result<Vec<u8>> {
        let CreateForwarder {
            address,
            alias,
            at_rust_node,
            ..
        } = dec.decode()?;
        let addr = MultiAddr::try_from(address.0.as_ref()).map_err(map_multiaddr_err)?;
        let route = crate::multiaddr_to_route(&addr)
            .ok_or_else(|| ApiError::generic("Invalid Multiaddr"))?;
        debug!(%addr, ?alias, "Handling CreateForwarder request");

        let forwarder = match alias.clone() {
            Some(alias) => {
                if at_rust_node {
                    RemoteForwarder::create_static_without_heartbeats(ctx, route.clone(), alias.to_string())
                        .await
                } else {
                    RemoteForwarder::create_static(ctx, route.clone(), alias.to_string()).await
                }
            }
            None => RemoteForwarder::create(ctx, route.clone()).await,
        };

        match forwarder {
            Ok(info) => {
                let worker_addr = info.worker_address().clone();
                let mut session = Session::new(worker_addr.clone(), Mode::Passive);
                let ctx = Arc::new(ctx.async_try_clone().await?);
                let alias = alias.as_deref().unwrap_or("").to_string(); // TODO
                let rte = route.clone();
                session.set_replacement(move |a| {
                    let w = worker_addr.clone();
                    let mut r = rte.clone();
                    let n = alias.clone();
                    let c = ctx.clone();
                    Box::pin(async move {
                        if let Some(a) = a {
                            let r: Route = r.modify().pop_front().prepend(a).into();
                            let f = if at_rust_node {
                                RemoteForwarder::create_static_without_heartbeats(&c, r, n).await?
                            } else {
                                RemoteForwarder::create_static(&c, r, n).await?
                            };
                            debug! {
                                target: "ockam_api::session",
                                addr = %f.worker_address(),
                                "started new forwarder"
                            }
                            Ok(f.worker_address().clone())
                        } else {
                            Ok(w)
                        }
                    })
                });
                let k = self.sessions.lock().unwrap().add(session);
                if let Some(a) = route.iter().next().cloned() {
                    let j = self.sessions.lock().unwrap().find(&a).map(Session::key);
                    let j = if let Some(j) = j {
                        self.sessions.lock().unwrap().add_dependency(k, j);
                        j
                    } else {
                        let s = Session::new(a.clone(), Mode::Active);
                        let j = self.sessions.lock().unwrap().add(s);
                        self.sessions.lock().unwrap().add_dependency(k, j);
                        j
                    };
                    if a.transport_type() == TCP {
                        let t = Arc::new(self.tcp_transport.async_try_clone().await?);
                        let mut sessions = self.sessions.lock().unwrap();
                        let s = sessions.session_mut(j).unwrap();
                        s.set_replacement(move |_| {
                            let t = t.clone();
                            let a = a.clone();
                            Box::pin(async move {
                                debug!(target: "ockam_api::session", addr = %a, "reconnecting");
                                let _ = t.disconnect(a.address()).await;
                                t.connect(a.address()).await?;
                                Ok(a)
                            })
                        });
                    }
                }
                let b = ForwarderInfo::from(info);
                debug!(
                    forwarding_route = %b.forwarding_route(),
                    remote_address = %b.remote_address(),
                    "CreateForwarder request processed, sending back response"
                );
                Ok(Response::ok(req.id()).body(b).to_vec()?)
            }
            Err(err) => {
                error!(?err, "Failed to create forwarder");
                Ok(Response::builder(req.id(), Status::InternalServerError)
                    .body(err.to_string())
                    .to_vec()?)
            }
        }
    }
}
