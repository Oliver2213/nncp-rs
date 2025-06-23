//! CLI module for NNCP commands and utilities
//!
//! This module provides command-line interface functionality for NNCP,
//! including context management, configuration, and command implementations.

pub mod commands;
pub mod config;
pub mod context;
pub mod init;
pub mod node;
pub mod via;

// Re-export commonly used types
pub use commands::Commands;
pub use config::{LocalNodeDiskConfig, RemoteNodeDiskConfig, DiskConfig};
pub use context::Context;
pub use via::{ViaArgs, apply_via_override, get_routing_target, parse_via_args};

// Re-export CLI parser
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = &nncp_rs::constants::LONG_ABOUT)]
#[command(propagate_version = true)]
/// Our command-line interface
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    /// NNCP configuration file
    /// Defaults to a local os-specific directory
    #[arg(short, long, value_name = "CONFIG_FILE", env="NNCP_RS_CONFIG")]
    pub config: Option<std::path::PathBuf>,
    /// Path to our ongoing log file
    #[arg(short, long, value_name="LOG_FILE", env="NNCP_RS_LOG_FILE")]
    pub log: Option<std::path::PathBuf>,
    /// Our node's spool directory, to store incoming and outgoing packets
    #[arg(short, long, env="NNCP_RS_SPOOL_DIR")]
    pub spool_directory: Option<std::path::PathBuf>,
}
