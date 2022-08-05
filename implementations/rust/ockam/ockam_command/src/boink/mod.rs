use clap::{Args, Subcommand};

// pub use bar::BarCommand;
pub use foo::FooCommand;

use crate::node::NodeOpts;
use crate::util::api::CloudOpts;
use crate::{CommandGlobalOpts, HELP_TEMPLATE};

// mod bar;
mod foo;

#[derive(Clone, Debug, Args)]
pub struct BoinkCommand {
    #[clap(flatten)]
    node_opts: NodeOpts,

    #[clap(flatten)]
    cloud_opts: CloudOpts,

    #[clap(subcommand)]
    subcommand: BoinkSubcommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum BoinkSubcommand {
    // /// Bar boinks
    // #[clap(display_order = 900, help_template = HELP_TEMPLATE)]
    // Bar(BarCommand),

    /// Foo boinks
    #[clap(display_order = 900, help_template = HELP_TEMPLATE)]
    Foo(FooCommand),
}

impl BoinkCommand {
    pub fn run(opts: CommandGlobalOpts, cmd: BoinkCommand) {
        match cmd.subcommand {
            // BoinkSubcommand::Bar(scmd) => BarCommand::run(opts, scmd),
            BoinkSubcommand::Foo(scmd) => FooCommand::run(opts, scmd),
        }
    }
}
