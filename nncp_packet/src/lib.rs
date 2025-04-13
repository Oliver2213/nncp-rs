//! NNCP Packet - Rust implementation of NNCP packet handling
//! 
//! This crate provides functionality for creating and handling NNCP packets
//! in their plain-text form and encrypted form.

mod magic;
mod packet;
mod error;
mod file;
mod exec;
mod freq;
mod trns;
mod ack;
mod constants;
mod mth;
mod eblob;

pub use magic::Magic;
pub use packet::{Packet, PacketType};
pub use error::Error;
pub use file::FilePacket;
pub use exec::{ExecPacket, ExecFatPacket};
pub use freq::FreqPacket;
pub use trns::TrnsPacket;
pub use ack::AckPacket;
pub use constants::*;
pub use mth::MTH;
pub use eblob::{EBlob, EBlobError, DEFAULT_S, DEFAULT_T, DEFAULT_P};

// Re-export the PacketContent trait directly
pub use packet::PacketContent;
