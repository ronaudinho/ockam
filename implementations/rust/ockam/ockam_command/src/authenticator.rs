use crate::util::{OckamConfig, connect_to, embedded_node, stop_node};
use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use ockam::{Context, Route, TcpTransport};
use ockam_api::{Request, multiaddr_to_route};
use ockam_api::authenticator::direct::{self, types::Enroller};
use ockam_api::authenticator::oauth2::{self, types::CredentialRequest};
use ockam_api::authenticator::IdentityId;
use ockam_api::nodes::types::{SetupAuthenticators, Oauth2Config};
use ockam_multiaddr::MultiAddr;

#[derive(Clone, Debug, Args)]
pub struct AuthenticatorCommand {
    #[clap(subcommand)]
    subcommand: AuthenticatorSubcommand,

    /// Override the default API node
    #[clap(short, long)]
    api_node: Option<String>,

    #[cfg(feature = "lmdb")]
    #[clap(long, short)]
    persist: Option<std::path::PathBuf>
}

#[derive(Clone, Debug, Subcommand)]
pub enum AuthenticatorSubcommand {
    SetupServices {
        #[clap(long, short)]
        authenticators: Vec<String>,
        
        #[clap(long)]
        auth0_url: Option<String>
    },
    RegisterEnroller {
        #[clap(long, short)]
        addr: MultiAddr,

        #[clap(long, short)]
        identity: String,
    },
    DeregisterEnroller {
        #[clap(long, short)]
        addr: MultiAddr,

        #[clap(long, short)]
        identity: String,
    },
    RegisterByOauth2Token {
        #[clap(long, short)]
        addr: MultiAddr,

        #[clap(long, short)]
        token: String,
    },
}

impl AuthenticatorCommand {
    pub fn run(cfg: &OckamConfig, cmd: AuthenticatorCommand) {
        match cmd.subcommand {
            AuthenticatorSubcommand::SetupServices { authenticators, auth0_url } => {
                let node = if let Some(node) = cfg.select_node(&cmd.api_node) {
                    node
                } else {
                    eprintln!("api node {:?} not found", cmd.api_node);
                    return
                };
                connect_to(node.port, (authenticators, auth0_url), setup)
            }
            AuthenticatorSubcommand::RegisterEnroller { addr, identity } =>
                embedded_node(register_enroller, (addr, identity)),
            AuthenticatorSubcommand::DeregisterEnroller { addr, identity } =>
                embedded_node(deregister_enroller, (addr, identity)),
            AuthenticatorSubcommand::RegisterByOauth2Token { addr, token } =>
                embedded_node(register_token, (addr, token))
        }
    }
}

async fn setup(ctx: Context, (authenticators, url): (Vec<String>, Option<String>), mut base: Route) -> Result<()> {
    let mut cfg = SetupAuthenticators::new();
    for a in &authenticators {
        match a.as_str() {
            "oauth2" => {
                if let Some(url) = &url {
                    let o = Oauth2Config::new(url);
                    cfg = cfg.with_oauth2(o)
                } else {
                    return Err(anyhow!("missing auth0-url option"))
                }
            }
            "direct"       => cfg = cfg.with_direct(),
            "direct-admin" => cfg = cfg.with_direct_admin(),
            _              => eprintln!("unknown authenticator {a}")
        }
    }
    let route: Route = base.modify().append("_internal.nodeman").into();
    let req = Request::post("/node/authenticators").body(cfg).to_vec()?;
    let res = ctx.send_and_receive(route, req).await?;
    stop_node(ctx).await
}

async fn register_enroller(ctx: Context, (addr, id): (MultiAddr, String)) -> Result<()> {
    TcpTransport::create(&ctx).await?;
    let r = multiaddr_to_route(&addr).ok_or_else(|| anyhow!("failed to parse address {addr}"))?;
    let mut c = direct::Client::new(r, &ctx).await?;
    c.register(&Enroller::new(IdentityId::new(id))).await?;
    println!("enroller registered successfully");
    stop_node(ctx).await
}

async fn deregister_enroller(ctx: Context, (addr, id): (MultiAddr, String)) -> Result<()> {
    TcpTransport::create(&ctx).await?;
    let r = multiaddr_to_route(&addr).ok_or_else(|| anyhow!("failed to parse address {addr}"))?;
    let mut c = direct::Client::new(r, &ctx).await?;
    c.deregister(&IdentityId::new(id)).await?;
    println!("enroller deregistered successfully");
    stop_node(ctx).await
}

async fn register_token(ctx: Context, (addr, token): (MultiAddr, String)) -> Result<()> {
    TcpTransport::create(&ctx).await?;
    let r = multiaddr_to_route(&addr).ok_or_else(|| anyhow!("failed to parse address {addr}"))?;
    let mut c = oauth2::Client::new(r, &ctx).await?;
    c.register(&CredentialRequest::new(token)).await?;
    println!("registered successfully");
    stop_node(ctx).await
}
