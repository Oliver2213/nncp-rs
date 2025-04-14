//! Error types for NNCP packet operations

use thiserror::Error;

/// Errors that can occur during NNCP packet operations
#[derive(Error, Debug)]
pub enum Error {
    /// Unknown magic number in packet
    #[error("Unknown magic number")]
    BadMagic,

    /// Unknown packet type
    #[error("Unknown packet type")]
    BadPacketType,

    /// Path is too long for packet
    #[error("Path is too long (max {0} bytes)")]
    PathTooLong(usize),

    /// I/O error during packet operations
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Invalid packet type for conversion
    #[error("Invalid packet type for conversion: expected {expected:?}, got {actual:?}")]
    InvalidPacketType {
        expected: crate::packet::PacketType,
        actual: crate::packet::PacketType,
    },
    
    /// Invalid UTF-8 in packet path
    #[error("Invalid UTF-8 in packet path")]
    InvalidUtf8,
    
    /// Command arguments are too long
    #[error("Command arguments are too long")]
    CommandTooLong,
    
    /// Too big for allowed size
    #[error("Too big for allowed size")]
    TooBig,
    
    /// Invalid recipient
    #[error("Invalid recipient")]
    InvalidRecipient,
    
    /// Unknown sender
    #[error("Unknown sender")]
    UnknownSender,
    
    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    /// Decryption error
    #[error("Decryption error: {0}")]
    Decryption(String),
}
