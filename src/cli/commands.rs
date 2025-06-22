//! NNCP command implementations

// Re-export the command modules
pub mod ack;
pub mod hash;
pub mod pkt;
pub mod stat;

// Re-export the command functions for backwards compatibility

use clap::Parser;
use clap::Subcommand;
use std::path::PathBuf;
use nncp_rs::constants;

#[derive(Subcommand)]
#[deny(missing_docs)]
/// all NNCP subcommands
pub enum Commands {
    /// Generates a node and prints it's base 32 encoded keys
    #[command(name="gen-node")]
    GenerateNode,
    /// Prints your local node's ID
    #[command(name="print-id")]
    PrintLocalNode {
        /// Include an emoji representation of the ID
        #[arg(short, long, default_value_t=false)]
        emojify: bool,
    },
    /// Calculate MTH hash of a file
    #[command(name="hash")]
    Hash {
        /// Read the file instead of stdin
        #[arg(short = 'f', long = "file")]
        file: Option<PathBuf>,
        /// Seek the file, hash, rewind, hash remaining
        #[arg(long, default_value_t = 0)]
        seek: u64,
        /// Force MTHFat implementation usage
        #[arg(long = "force-fat", default_value_t = false)]
        force_fat: bool,
        /// Progress showing
        #[arg(long, default_value_t = false)]
        progress: bool,
        /// Print MTH steps calculations
        #[arg(long, default_value_t = false)]
        debug: bool,
    },
    /// Parse and display NNCP packet information
    #[command(name="pkt")]
    Pkt {
        /// Print packet overhead calculations
        #[arg(long, default_value_t = false)]
        overheads: bool,
        /// Write decrypted/parsed payload to stdout
        #[arg(long, default_value_t = false)]
        dump: bool,
        /// Try to zstd decompress dumped data
        #[arg(long, default_value_t = false)]
        decompress: bool,
    },
    /// Show queue statistics
    #[command(name="stat")]
    Stat {
        /// Show statistics for specific node only
        #[arg(short, long)]
        node: Option<String>,
        /// Show individual packet listing
        #[arg(long, default_value_t = false)]
        pkt: bool,
    },
    /// Send packet receipt acknowledgement
    #[command(name="ack")]
    Ack {
        /// ACK all rx packets for all nodes
        #[arg(long, default_value_t = false)]
        all: bool,
        /// ACK rx packets for specific nodes (comma-separated)
        #[arg(short, long)]
        node: Option<String>,
        /// ACK only that specific packet
        #[arg(long)]
        pkt: Option<String>,
        /// Outbound packet niceness
        #[arg(long, default_value = "N")]
        nice: String,
        /// Minimal required resulting packet size in KiB
        #[arg(long)]
        minsize: Option<i64>,
        /// Override Via path to destination node (ignored with --all)
        #[arg(long)]
        via: Option<String>,
        /// Print only errors
        #[arg(short, long, default_value_t = false)]
        quiet: bool,
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = &constants::LONG_ABOUT)]
#[command(propagate_version = true)]
/// Our command-line interface
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    /// NNCP configuration file
    /// Defaults to a local os-specific directory
    #[arg(short, long, value_name = "CONFIG_FILE", env="NNCP_RS_CONFIG")]
    pub config: Option<PathBuf>,
    /// Path to our ongoing log file
    #[arg(short, long, value_name="LOG_FILE", env="NNCP_RS_LOG_FILE")]
    pub log: Option<PathBuf>,
    /// Our node's spool directory, to store incoming and outgoing packets
    #[arg(short, long, env="NNCP_RS_SPOOL_DIR")]
    pub spool_directory: Option<PathBuf>,
}

// Re-export the command functions for backwards compatibility
pub use ack::send_acknowledgements;
pub use hash::hash_file;
pub use pkt::parse_packet;
pub use stat::show_statistics;