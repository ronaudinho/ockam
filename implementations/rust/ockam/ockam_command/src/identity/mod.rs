mod create;
mod get;

pub(crate) use create::CreateCommand;
pub(crate) use get::GetCommand;

use crate::{util::OckamConfig, HELP_TEMPLATE};
use clap::{Args, Subcommand};

#[derive(Clone, Debug, Args)]
pub struct IdentityCommand {
    #[clap(subcommand)]
    subcommand: IdentitySubcommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum IdentitySubcommand {
    /// Create Identity
    #[clap(display_order = 900, help_template = HELP_TEMPLATE)]
    Create(CreateCommand),

    /// Get identity information.
    #[clap(display_order = 900, help_template = HELP_TEMPLATE)]
    Get(GetCommand),
}

impl IdentityCommand {
    pub fn run(cfg: &OckamConfig, command: IdentityCommand) {
        match command.subcommand {
            IdentitySubcommand::Create(command) => CreateCommand::run(cfg, command),
            IdentitySubcommand::Get(command) => GetCommand::run(cfg, command),
        }
        .unwrap()
    }
}
