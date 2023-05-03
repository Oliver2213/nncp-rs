//! nncp-rs - node to node copy tools
use clap::Parser;
use nncp_rs::cli;

fn main() {
    let cli = cli::Cli::parse();
    match &cli.command {
        cli::Commands::GenerateNode => cli::generate_node(),
    }
}
