//! nncp-rs - node to node copy tools

use std::path::PathBuf;
use clap::Parser;
use nncp_rs::commands;
use nncp_rs::constants;

#[derive(Parser)]
#[command(author, version, about, long_about = &constants::LONG_ABOUT)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: commands::Commands,
    /// NNCP configuration file
    #[arg(short, long, value_name = "CONFIG_FILE")]
    config: Option<PathBuf>,}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        commands::Commands::GenerateNode => commands::generate_node(),
    }
}
