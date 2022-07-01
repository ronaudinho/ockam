use crate::util::embedded_node;
use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use ockam::{Context, TcpTransport};
use ockam_api::authenticator::IdentityId;
use ockam_api::authenticator::direct::{self, types::Enroller};
use ockam_multiaddr::MultiAddr;

#[derive(Clone, Debug, Args)]
pub struct AuthenticatorCommand {
    #[clap(subcommand)]
    subcommand: AuthenticatorSubcommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum AuthenticatorSubcommand {
    RegisterEnroller {
        #[clap(long, short)]
        address: MultiAddr,

        #[clap(long, short)]
        identity: String,
    },
    DeregisterEnroller {
        #[clap(long, short)]
        address: MultiAddr,

        #[clap(long, short)]
        identity: String
    }
}

impl AuthenticatorCommand {
    pub fn run(c: AuthenticatorCommand) {
        embedded_node(run_impl, c.subcommand)
    }
}

async fn run_impl(mut ctx: Context, cmd: AuthenticatorSubcommand) -> Result<()> {
    TcpTransport::create(&ctx).await?;
    match &cmd {
        AuthenticatorSubcommand::RegisterEnroller { address, identity } => {
            let r = ockam_api::multiaddr_to_route(address)
                .ok_or_else(|| anyhow!("failed to parse address: {address}"))?;
            let mut c = direct::Client::new(r, &ctx).await?;
            c.register(&Enroller::new(IdentityId::new(identity))).await?;
            println!("enroller registered successfully")
        }
        AuthenticatorSubcommand::DeregisterEnroller { address, identity } => {
            let r = ockam_api::multiaddr_to_route(address)
                .ok_or_else(|| anyhow!("failed to parse address: {address}"))?;
            let mut c = direct::Client::new(r, &ctx).await?;
            c.deregister(&IdentityId::new(identity)).await?;
            println!("enroller deregistered successfully")
        }
    }
    ctx.stop().await?;
    Ok(())
}
