//! NNCP - Node to Node Copy Protocol library
//! 
//! This crate provides functionality for the NNCP protocol, including
//! packet handling, encryption, signing, and node management.

pub mod constants;
pub mod nncp;
pub mod errors;
pub mod packet;
pub mod magic;
pub mod routing;

// Re-export key components for easier access
pub use errors::NNCPError;
pub use packet::{
    Packet, PacketType, PacketContent,
    FilePacket, FreqPacket, ExecPacket, ExecFatPacket, TrnsPacket, AckPacket,
    MTH, EBlob, Error as PacketError
};
