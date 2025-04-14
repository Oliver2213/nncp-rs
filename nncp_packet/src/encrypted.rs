//! Encrypted packet implementation for NNCP
//! 
//! This module provides functionality for creating and handling encrypted packets
//! using the EBlob encryption for secure communication between nodes.

use crate::eblob::{EBlob, EBlobError};
use crate::packet::{Packet, PacketContent, PacketType};
use crate::Error;
use serde::{Serialize, Deserialize};

/// Encrypted packet structure
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedPacket {
    /// The encrypted packet data
    pub encrypted_data: Vec<u8>,
}

impl EncryptedPacket {
    /// Create a new encrypted packet from a plain packet
    ///
    /// * `packet` - The plain packet to encrypt
    /// * `password` - Password for encryption
    /// * `s_cost` - Space cost parameter for Balloon hashing
    /// * `t_cost` - Time cost parameter for Balloon hashing
    /// * `p_cost` - Parallelism parameter for Balloon hashing
    pub fn new(
        packet: &Packet,
        password: &[u8],
        s_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Self, Error> {
        // Serialize the packet
        let packet_data = bincode::serialize(packet)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        
        // Encrypt the packet data
        let encrypted_data = EBlob::new(s_cost, t_cost, p_cost, password, &packet_data)
            .map_err(|e| Error::Encryption(e.to_string()))?;
        
        Ok(Self { encrypted_data })
    }
    
    /// Decrypt the encrypted packet
    ///
    /// * `password` - Password for decryption
    pub fn decrypt(&self, password: &[u8]) -> Result<Packet, Error> {
        // Decrypt the packet data
        let packet_data = EBlob::decrypt(&self.encrypted_data, password)
            .map_err(|e| Error::Decryption(e.to_string()))?;
        
        // Deserialize the packet
        let packet: Packet = bincode::deserialize(&packet_data)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        
        Ok(packet)
    }
    
    /// Decrypt and convert to a specific packet type
    ///
    /// * `password` - Password for decryption
    pub fn decrypt_as<T: PacketContent>(&self, password: &[u8]) -> Result<(T, u8), Error> {
        let packet = self.decrypt(password)?;
        let nice = packet.nice;
        let content = T::from_packet(&packet)?;
        Ok((content, nice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FilePacket;
    
    #[test]
    fn test_encrypted_packet_roundtrip() {
        // Create a file packet
        let file_packet = FilePacket {
            path: "test/file.txt".to_string(),
        };
        
        // Convert to a plain packet
        let packet = file_packet.to_packet(5).unwrap();
        
        // Password for encryption
        let password = b"test_password";
        
        // Create an encrypted packet
        let encrypted = EncryptedPacket::new(&packet, password, 4, 4, 1).unwrap();
        
        // Decrypt the packet
        let decrypted = encrypted.decrypt(password).unwrap();
        
        // Verify the decrypted packet matches the original
        assert_eq!(decrypted.packet_type, packet.packet_type);
        assert_eq!(decrypted.nice, packet.nice);
        assert_eq!(decrypted.path_len, packet.path_len);
        assert_eq!(&decrypted.path[..decrypted.path_len as usize], 
                  &packet.path[..packet.path_len as usize]);
        
        // Test decrypt_as
        let (file_packet_decrypted, nice) = encrypted.decrypt_as::<FilePacket>(password).unwrap();
        assert_eq!(file_packet_decrypted.path, file_packet.path);
        assert_eq!(nice, 5);
    }
    
    #[test]
    fn test_encrypted_packet_wrong_password() {
        // Create a file packet
        let file_packet = FilePacket {
            path: "test/file.txt".to_string(),
        };
        
        // Convert to a plain packet
        let packet = file_packet.to_packet(5).unwrap();
        
        // Password for encryption
        let password = b"test_password";
        let wrong_password = b"wrong_password";
        
        // Create an encrypted packet
        let encrypted = EncryptedPacket::new(&packet, password, 4, 4, 1).unwrap();
        
        // Attempt to decrypt with wrong password should fail
        let result = encrypted.decrypt(wrong_password);
        assert!(result.is_err());
    }
}
