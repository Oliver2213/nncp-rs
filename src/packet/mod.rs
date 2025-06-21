//! Packet handling for NNCP
//! 
//! This module provides functionality for creating, parsing, and
//! manipulating NNCP packets.

mod error;
mod packet_impl;
mod ack;
mod exec;
mod file;
mod freq;
mod trns;
mod mth;
mod eblob;
pub mod encrypted;

// Re-export key components
pub use error::Error;
pub use packet_impl::{Packet, PacketType, PacketContent};
pub use ack::AckPacket;
pub use exec::{ExecPacket, ExecFatPacket};
pub use file::FilePacket;
pub use freq::FreqPacket;
pub use trns::TrnsPacket;
pub use mth::MTH;
pub use eblob::{EBlob, EBlobError, DEFAULT_S, DEFAULT_T, DEFAULT_P};
pub use encrypted::EncryptedPacket;

// Re-export from blake3 for MTH
pub use blake3::Hash;
