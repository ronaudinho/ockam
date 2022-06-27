use crate::old::identity::load_or_create_identity;
use crate::util::{embedded_node, multiaddr_to_route};
use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use minicbor::Decoder;
use ockam::identity::{Identity, IdentityIdentifier, IdentityVault};
use ockam::{Context, TcpTransport, identity::TrustIdentifierPolicy};
use ockam::authenticated_storage::InMemoryStorage;
use ockam_api::{Request, Response, Status};
use ockam_api::authority::types::{CredentialRequest, Oauth2, Signature, Signed};
use ockam_core::route;
use ockam_multiaddr::MultiAddr;

#[derive(Clone, Debug, Args)]
pub struct AuthorityCommand {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    Oauth2 {
        /// Address to connect to.
        #[clap(long)]
        addr: MultiAddr,
        
        /// Their identifier.
        #[clap(long)]
        id: String,
        
        /// Access token.
        #[clap(long)]
        token: String
    }
}

impl AuthorityCommand {
    pub fn run(c: AuthorityCommand) {
        embedded_node(run_impl, c.cmd)
    }
}

async fn run_impl(ctx: Context, cmd: Command) -> Result<()> {
    TcpTransport::create(&ctx).await?;
    let this = load_or_create_identity(&ctx, false).await?;
    let ident = this.identifier()?;
    let store = InMemoryStorage::new();
    match cmd {
        Command::Oauth2 { addr, id, token } => {
            let route = multiaddr_to_route(&addr).ok_or_else(|| anyhow!("invalid: {addr}"))?;
            let policy = TrustIdentifierPolicy::new(id.as_str().try_into()?);
            let channel = this.create_secure_channel(route, policy, &store).await?;
            let req = oauth2_request(&this, &ident, token.as_str()).await?;
            let route = route![channel, "authority"];
            let vec: Vec<u8> = ctx.send_and_receive(route, req).await?;
            let mut dec = Decoder::new(&vec);
            let res: Response = dec.decode()?;
            if res.status() != Some(Status::Ok) {
                return Err(anyhow!("todo"))
            }
            let a: Signed = dec.decode()?;
            dbg!(a);
        }
    }
    Ok(())
}

async fn oauth2_request<V>(this: &Identity<V>, id: &IdentityIdentifier, token: &str) -> Result<Vec<u8>>
where
    V: IdentityVault
{
    let dat = minicbor::to_vec(Oauth2::new(token))?;
    let sig = this.create_signature(&dat).await?;
    let req = Request::post("/sign")
        .body(CredentialRequest::Oauth2 {
            data: &dat,
            signature: Signature::new(id.key_id().as_str(), sig.as_ref())
        })
        .to_vec()?;
    Ok(req)
}
