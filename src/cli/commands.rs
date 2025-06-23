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
use super::Context;

#[derive(Subcommand)]
#[deny(missing_docs)]
/// all NNCP subcommands
pub enum Commands {
    /// Initialize NNCP configuration and spool directory
    Init {
        /// Directory to create config in (uses OS-specific config directory if not specified)
        #[arg(short, long)]
        directory: Option<PathBuf>,
        /// Spool directory path (uses OS-specific spool directory if not specified)
        #[arg(short, long)]
        spool: Option<PathBuf>,
    },
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


// Re-export the command functions for backwards compatibility
pub use ack::send_acknowledgements;
pub use hash::hash_file;
pub use pkt::parse_packet;
pub use stat::show_statistics;
