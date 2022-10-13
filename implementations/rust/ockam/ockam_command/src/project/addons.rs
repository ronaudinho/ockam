use anyhow::Context as _;
use clap::{Args, Subcommand};

use ockam::Context;
use crate::help;
use crate::node::util::{delete_embedded_node, start_embedded_node};
use crate::util::api::{self, CloudOpts};
use crate::project::util::config;
use crate::util::{node_rpc, RpcBuilder};
use crate::CommandGlobalOpts;

/// Configure and enable an addon on the given project
#[derive(Clone, Debug, Args)]
#[command(hide = help::hide(), subcommand_required = true)]
pub struct ConfigureAddonCommand {

    #[command(subcommand)]
    subcommand: AddonSubcommand
}

#[derive(Clone, Debug, Subcommand)]
pub enum AddonSubcommand {
    Okta(OktaConfigCommand),
}

impl ConfigureAddonCommand {
    pub fn run(self, options: CommandGlobalOpts) {
        match self.subcommand {
            AddonSubcommand::Okta(c) => c.run(options),
        }
    }
}

/// Configure Okta' addon
#[derive(Clone, Debug, Args)]
#[command()]
pub struct OktaConfigCommand {
    /// Name of the project.
    #[arg(display_order = 1001)]
    pub name: String,

    #[arg(display_order = 1002)]
    pub tenant_url: String,

    #[arg(display_order = 1003)]
    pub certificate: String,

    #[command(flatten)]
    pub cloud_opts: CloudOpts,
}

impl OktaConfigCommand {
    pub fn run(self, options: CommandGlobalOpts) {
        node_rpc(rpc, (options, self));
    }
}

async fn rpc(mut ctx: Context, (opts, cmd): (CommandGlobalOpts, OktaConfigCommand)) -> crate::Result<()> {
    run_impl(&mut ctx, opts, cmd).await
}

async fn run_impl(
    ctx: &mut Context,
    opts: CommandGlobalOpts,
    cmd: OktaConfigCommand,
) -> crate::Result<()> {
    let node_name = start_embedded_node(ctx, &opts.config).await?;

    // Lookup project
    let id = match config::get_project(&opts.config, &cmd.name) {
        Some(id) => id,
        None => {
            config::refresh_projects(ctx, &opts, &node_name, &cmd.cloud_opts.route(), None).await?;
            config::get_project(&opts.config, &cmd.name)
                .context(format!("Project '{}' does not exist", cmd.name))?
        }
    };

    // Send request
    let mut rpc = RpcBuilder::new(ctx, &opts, &node_name).build();
    rpc.request(api::project::okta_addon_config(&id, &cmd)).await?;
    rpc.is_ok()?;
    delete_embedded_node(&opts.config, rpc.node_name()).await;
    Ok(())
}
