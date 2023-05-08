//! nncp-rs - node to node copy tools

use clap::Parser;
mod cli;
use anyhow::Error;

fn main() -> Result<(), Error> {
    env_logger::init();
    // Start with a default context and override it with any options passed in:
    let mut ctx = cli::Context::default();
    let cli = cli::Cli::parse();
    // These unwraps are safe because we explicitly check that !is_none before!
    if !cli.config.is_none() {
        ctx.config_path = cli.config.unwrap();
    }
    if !cli.log.is_none() {
        ctx.log_path = cli.log.unwrap();
    }
    if !cli.spool_directory.is_none() {
        ctx.spool_path = cli.spool_directory.unwrap();
    }
    ctx.load_config()?;
    match &cli.command {
        cli::Commands::GenerateNode => cli::node::generate_node(ctx),
        cli::Commands::PrintLocalNode{emojify} => cli::node::print_local_node(ctx, *emojify),
    }
    Ok(())
}
