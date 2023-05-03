//! Subcommands

use clap::Parser;
use clap::Subcommand;
use nncp_rs::constants;
use std::path::PathBuf;

#[derive(Subcommand)]
#[deny(missing_docs)]
/// all NNCP subcommands
pub enum Commands {
    /// Generates a new node and prints it's base 32 encoded keys to stdout
    GenerateNode,
}

#[derive(Parser)]
#[command(author, version, about, long_about = &constants::LONG_ABOUT)]
#[command(propagate_version = true)]
/// Our command-line interface
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    /// NNCP configuration file
    #[arg(short, long, value_name = "CONFIG_FILE")]
    pub config: Option<PathBuf>,
}