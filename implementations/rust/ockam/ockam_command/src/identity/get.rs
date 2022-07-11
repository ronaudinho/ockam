use anyhow::Result;
use crate::util::{api, connect_to, stop_node, OckamConfig};
use clap::Args;
use ockam::Context;
use ockam_api::{Response, Status, nodes::types::IdentityInfo};
use ockam_core::Route;

#[derive(Clone, Debug, Args)]
pub struct GetCommand {
    /// Override the default API node
    #[clap(short, long)]
    pub api_node: Option<String>,
}

impl GetCommand {
    pub fn run(cfg: &OckamConfig, command: GetCommand) -> anyhow::Result<()> {
        let port = match cfg.select_node(&command.api_node) {
            Some(cfg) => cfg.port,
            None => {
                eprintln!("No such node available.  Run `ockam node list` to list available nodes");
                std::process::exit(-1);
            }
        };

        connect_to(port, (), get_identity);

        Ok(())
    }
}

pub async fn get_identity(ctx: Context, _: (), mut base_route: Route) -> Result<()> {
    let resp: Vec<u8> = ctx
        .send_and_receive(
            base_route.modify().append("_internal.nodeman"),
            api::get_identity()?,
        )
        .await?;

    let mut dec = minicbor::Decoder::new(&resp);
    let response = dec.decode::<Response>()?;

    match response.status() {
        Some(Status::Ok) => {
            let id: IdentityInfo = dec.decode()?;
            eprintln!("identity Id = {}", id.identity().as_str())
        }
        Some(Status::NotFound) => {
            eprintln!("no identity found")
        }
        _ => {
            eprintln!("An error occurred while getting identity information",)
        }
    }

    stop_node(ctx).await
}

