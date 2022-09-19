use std::sync::Arc;
use std::time::Duration;

use minicbor::Decoder;

use ockam::compat::futures::FutureExt;
use ockam::remote::RemoteForwarder;
use ockam::{Result, Route};
use ockam_core::AsyncTryClone;
use ockam_core::api::{Request, Response, Status, Id};
use ockam_multiaddr::MultiAddr;
use ockam_multiaddr::proto::DnsAddr;
use ockam_node::Context;
use ockam_node::tokio::time::timeout;

use crate::error::ApiError;
use crate::nodes::models::forwarder::{CreateForwarder, ForwarderInfo};
use crate::nodes::service::map_multiaddr_err;
use crate::nodes::NodeManager;
use crate::session::Session;

enum ForwarderType {
    Local,
    Remote
}

async fn create_connection(manager: Arc<NodeManager>, addr: MultiAddr) -> Result<()> {
    // let mut protos = addr.iter();
    // if let Some(p) = protos.next() {
    //     match p.code() {
    //         DnsAddr
    // } else {
    // }

    Ok(())
}

impl NodeManager {
    pub(super) async fn create_forwarder(
        &mut self,
        ctx: &mut Context,
        rid: Id,
        dec: &mut Decoder<'_>,
    ) -> Result<Vec<u8>> {
        let req: CreateForwarder = dec.decode()?;

        let route = crate::multiaddr_to_route(&req.address)
            .ok_or_else(|| ApiError::generic("Invalid Multiaddr"))?;

        debug!(addr = %req.address, alias = ?req.alias, "Handling CreateForwarder request");

        let (forwarder, typ) = match req.alias.clone() {
            Some(alias) => {
                let r = route.clone();
                let a = alias.to_string();
                let f = if req.at_rust_node {
                    RemoteForwarder::create_static_without_heartbeats(ctx, r, a).await
                } else {
                    RemoteForwarder::create_static(ctx, r, a).await
                };
                (f, ForwarderType::Remote)
            }
            None => {
                let f = RemoteForwarder::create(ctx, route.clone()).await;
                (f, ForwarderType::Local)
            }
        };

        match forwarder {
            Ok(info) => {
                if matches!(typ, ForwarderType::Remote) {
                    self.f(&req.address);
                }
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

    fn f(&mut self, addr: &MultiAddr) {
        // let worker_addr = info.worker_address().clone();
        // let mut session = Session::new(worker_addr.clone());
        // let ctx = Arc::new(ctx.async_try_clone().await?);
        // let alias = alias.as_deref().unwrap_or("").to_string(); // TODO
        // let rte = route.clone();
        // session.set_replacement(move || {
        //     let w = worker_addr.clone();
        //     let mut r = rte.clone();
        //     let n = alias.clone();
        //     let c = ctx.clone();
        //     Box::pin(async move {
        //         if let Some(a) = a {
        //             let r: Route = r.modify().pop_front().prepend(a).into();
        //             debug! {
        //                 target: "ockam_api::session",
        //                 route = %r,
        //                 "creating new remote forwarder"
        //             }
        //             let f = if at_rust_node {
        //                 RemoteForwarder::create_static_without_heartbeats(&c, r, n).boxed()
        //             } else {
        //                 RemoteForwarder::create_static(&c, r, n).boxed()
        //             };
        //             match timeout(MAX_CONNECT, f).await {
        //                 Err(_) => {
        //                     warn! {
        //                         target: "ockam_api::session",
        //                         "timeout creating new remote forwarder"
        //                     }
        //                     Err(ApiError::generic("timeout"))
        //                 }
        //                 Ok(Err(e)) => {
        //                     warn! {
        //                         target: "ockam_api::session",
        //                         err = %e,
        //                         "error creating new remote forwarder"
        //                     }
        //                     Err(e)
        //                 }
        //                 Ok(Ok(a)) => Ok(a.worker_address().clone())
        //             }
        //         } else {
        //             Ok(w)
        //         }
        //     })
        // });
        // let k = self.sessions.lock().unwrap().add(session);
        // if let Some(a) = route.iter().next().cloned() {
        //     let j = self.sessions.lock().unwrap().find(&a).map(Session::key);
        //     if let Some(j) = j {
        //         self.sessions.lock().unwrap().add_dependency(k, j);
        //     } else {
        //         let s = Session::new(a.clone(), Mode::Active);
        //         let j = self.sessions.lock().unwrap().add(s);
        //         self.sessions.lock().unwrap().add_dependency(k, j);
        //     }
        // }
    }

}
