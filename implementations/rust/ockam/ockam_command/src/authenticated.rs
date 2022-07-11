use crate::util::embedded_node;
use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use data_encoding::BASE32_DNSSEC;
use ockam::{Context, TcpTransport};
use ockam_api::auth;
use ockam_multiaddr::MultiAddr;

#[derive(Clone, Debug, Args)]
pub struct AuthenticatedCommand {
    #[clap(subcommand)]
    subcommand: AuthenticatedSubcommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum AuthenticatedSubcommand {
    /// Get attribute value.
    Get {
        /// Address to connect to.
        #[clap(long, short)]
        addr: MultiAddr,

        /// Subject identifier
        #[clap(long, short, forbid_empty_values = true)]
        id: String,

        /// Attribute key.
        #[clap(long, short, forbid_empty_values = true)]
        key: String,
    },
    /// Delete attribute.
    Del {
        /// Address to connect to.
        #[clap(long, short)]
        addr: MultiAddr,

        /// Subject identifier
        #[clap(long, short, forbid_empty_values = true)]
        id: String,

        /// Attribute key.
        #[clap(long, short, forbid_empty_values = true)]
        key: String,
    }
}

impl AuthenticatedCommand {
    pub fn run(c: AuthenticatedCommand) {
        embedded_node(run_impl, c.subcommand)
    }
}

async fn run_impl(mut ctx: Context, cmd: AuthenticatedSubcommand) -> anyhow::Result<()> {
    TcpTransport::create(&ctx).await?;
    match &cmd {
        AuthenticatedSubcommand::Get { addr, id, key } => {
            let mut c = client(addr, &ctx).await?;
            if let Some(val) = c.get(id, key).await? {
                println!("{}", BASE32_DNSSEC.encode(val))
            } else {
                println!("no value found for {key}")
            }
        }
        AuthenticatedSubcommand::Del { addr, id, key } => {
            let mut c = client(addr, &ctx).await?;
            c.del(id, key).await?;
        }
    }
    ctx.stop().await?;
    Ok(())
}

async fn client(addr: &MultiAddr, ctx: &Context) -> Result<auth::Client> {
    let to = ockam_api::multiaddr_to_route(addr)
        .ok_or_else(|| anyhow!("failed to parse address: {addr}"))?;
    let cl = auth::Client::new(to, ctx).await?;
    Ok(cl)
}
