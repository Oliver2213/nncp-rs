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
    #[arg(short, long, value_name = "CONFIG_FILE", env="NNCP_RS_CONFIG")]
    pub config: Option<PathBuf>,
    /// Path to our ongoing log file
    #[arg(short, long, value_name="LOG_FILE", env="NNCP_RS_LOG_FILE")]
    pub log: Option<PathBuf>,
    /// Our node's spool directory, to store incoming and outgoing packets
    #[arg(short, long, env="NNCP_RS_SPOOL_DIR")]
    pub spool_directory: Option<PathBuf>,
}