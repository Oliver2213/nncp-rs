//! nncp-rs - node to node copy tools

mod cli;
use anyhow::Error;
use log::debug;
use clap::Parser;

fn main() -> Result<(), Error> {
    env_logger::init();
    // Start with a default context and override it with any options passed in:
    let mut ctx = cli::Context::default();
    let cli = cli::Cli::parse();
    debug!("Parsed command-line arguments");
    if cli.config.is_some() {
        ctx.config_path = cli.config.unwrap();
    }
    if cli.log.is_some() {
        ctx.log_path = cli.log.unwrap();
    }
    if cli.spool_directory.is_some() {
        ctx.spool_path = cli.spool_directory.unwrap();
    }
    ctx.load_config()?;
    match &cli.command {
        cli::Commands::Init { directory, spool } => {
            cli::init::init(ctx, directory.clone(), spool.clone())?
        },
        cli::Commands::GenerateNode => cli::node::generate_node(ctx)?,
        cli::Commands::PrintLocalNode{emojify} => cli::node::print_local_node(ctx, *emojify),
        cli::Commands::Hash { file, seek, force_fat, progress, debug } => {
            cli::commands::hash_file(file, *seek, *force_fat, *progress, *debug)?
        },
        cli::Commands::Pkt { overheads, dump, decompress } => {
            cli::commands::parse_packet(*overheads, *dump, *decompress)?
        },
        cli::Commands::Stat { node, pkt } => {
            cli::commands::show_statistics(ctx, node.as_deref(), *pkt)?
        },
        cli::Commands::Ack { all, node, pkt, nice, minsize, via, quiet } => {
            cli::commands::send_acknowledgements(
                ctx,
                *all,
                node.as_deref(),
                pkt.as_deref(),
                nice,
                *minsize,
                via.as_deref(),
                *quiet
            )?
        },
    }
    Ok(())
}
