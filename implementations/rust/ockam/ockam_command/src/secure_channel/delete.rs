use crate::util::get_final_element;
use crate::util::{api, connect_to, exitcode, stop_node};
use crate::CommandGlobalOpts;
use anyhow::{anyhow, Context};
use clap::Args;
use minicbor::Decoder;
use ockam::identity::IdentityIdentifier;
use ockam_api::error::ApiError;
use ockam_api::nodes::models::secure_channel::DeleteSecureChannelResponse;
use ockam_api::nodes::NODEMANAGER_ADDR;
use ockam_api::{clean_multiaddr, route_to_multiaddr};
use ockam_core::api::{Response, Status};
use ockam_core::{route, Route};
use ockam_multiaddr::MultiAddr;
use tracing::debug;
use ockam::Address;

#[derive(Clone, Debug, Args)]
pub struct SecureChannelNodeOpts {
    /// Node that will initiate the secure channel
    #[clap(
        global = true,
        short,
        long,
        value_name = "NODE",
        default_value = "default"
    )]
    pub from: String,
}

#[derive(Clone, Debug, Args)]
pub struct DeleteCommand {
    #[clap(flatten)]
    node_opts: SecureChannelNodeOpts,

    channel: Address,
}

impl DeleteCommand {
    pub fn run(mut self, opts: CommandGlobalOpts) -> anyhow::Result<()> {
        let cfg = opts.config;
        let node = get_final_element(&self.node_opts.from);
        let port = match cfg.select_node(node) {
            Some(cfg) => cfg.port,
            None => {
                eprintln!("No such node available.  Run `ockam node list` to list available nodes");
                std::process::exit(exitcode::IOERR);
            }
        };

        self.node_opts.from = node.to_string();

        connect_to(port, self, delete_connector);

        Ok(())
    }
}

async fn delete_connector(
    ctx: ockam::Context,
    cmd: DeleteCommand,
    mut base_route: Route,
) -> anyhow::Result<()> {

    let response: Vec<u8> = ctx
        .send_and_receive(
            base_route.modify().append(NODEMANAGER_ADDR),
            api::delete_secure_channel(cmd.channel)?,
        )
        .await
        .context("Failed to process request")?;

    let mut dec = Decoder::new(&response);
    let header = dec.decode::<Response>()?;
    debug!(?header, "Received response");

    let res = match header.status() {
        Some(Status::Ok) => {
            Ok(dec.decode::<DeleteSecureChannelResponse>()?)           
        }
        Some(Status::InternalServerError) => {
            let err = dec
                .decode::<String>()
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(anyhow!(
                "An error occurred while processing the request: {err}"
            ))
        },
        Some(status) => Err(anyhow!("Unexpected response received from node: {}", status)),
        _ => Err(anyhow!("Unexpected response received from node")),
    };
    match res {
        Ok(resp) => println!("deleted {}", resp.channel),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(exitcode::IOERR);
        }
    };

    stop_node(ctx).await
}



