//! NNCP subcommands

use base32::encode;
use base32::Alphabet::RFC4648;
use clap::Parser;
use clap::Subcommand;
use nncp_rs::constants;
use nncp_rs::nncp::LocalNNCPNode;
use std::path::PathBuf;




