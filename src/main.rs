//! nncp-rs - node to node copy tools
use clap::Parser;
mod cli;

fn main() {
    let cli = cli::Cli::parse();
    match &cli.command {
        cli::Commands::GenerateNode => cli::generate_node(),
    }
}
