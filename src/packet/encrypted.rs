//! Encrypted packet implementation for NNCP
//!
//! This module provides functionality for encrypted packets.

use crate::packet::Error;

/// Encrypted packet for NNCP
#[derive(Debug, Clone)]
pub struct EncryptedPacket {
    /// The encrypted packet data
    pub encrypted_data: Vec<u8>,
}

impl EncryptedPacket {
    /// Create a new encrypted packet with the given data
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            encrypted_data: data,
        }
    }
    
    /// Get the encrypted data
    pub fn data(&self) -> &[u8] {
        &self.encrypted_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypted_packet() {
        let data = vec![1, 2, 3, 4, 5];
        let packet = EncryptedPacket::new(data.clone());
        
        assert_eq!(packet.data(), &data);
    }
}
