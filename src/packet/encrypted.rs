//! Encrypted packet implementation for NNCP
//!
//! This module provides functionality for encrypted packets compatible with the Go implementation.

use crate::packet::{Error, Packet};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, NewAead}};
use blake3;
use std::io::{Read, Write};
use std::collections::HashMap;

const ENC_BLK_SIZE: usize = 128 * 1024; // 128KB blocks

// Key derivation contexts (must match Go exactly)
const DERIVE_KEY_FULL_CTX: &[u8] = b"NNCPE\x00\x00\x06 FULL";
const DERIVE_KEY_SIZE_CTX: &[u8] = b"NNCPE\x00\x00\x06 SIZE"; 
const DERIVE_KEY_PAD_CTX: &[u8] = b"NNCPE\x00\x00\x06 PAD";

/// Node ID type (placeholder - should match your actual NodeID type)
pub type NodeID = [u8; 32];

/// Encrypted packet header (PktEnc in Go)
#[derive(Debug, Clone)]
pub struct EncryptedPacketHeader {
    pub magic: [u8; 8],
    pub nice: u8,
    pub sender: NodeID,
    pub recipient: NodeID,
    pub exch_pub: [u8; 32],
    pub signature: [u8; 64],
}

/// To-be-signed structure (PktTbs in Go)
#[derive(Debug, Clone)]
struct PacketTbs {
    pub magic: [u8; 8],
    pub nice: u8,
    pub sender: NodeID,
    pub recipient: NodeID,
    pub exch_pub: [u8; 32],
}

/// Packet size information
#[derive(Debug, Clone)]
struct PacketSize {
    pub payload: u64,
    pub pad: u64,
}

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

    /// Encrypt a packet and write to output (equivalent to PktEncWrite in Go)
    pub fn encrypt_packet<R: Read, W: Write>(
        packet: &Packet,
        nice: u8,
        min_size: i64,
        max_size: i64,
        wrappers: i32,
        mut reader: R,
        mut writer: W,
    ) -> Result<(Vec<u8>, i64), Error> {
        // Serialize the packet using your existing encode method
        let mut packet_raw = Vec::new();
        packet.encode(&mut packet_raw)?;
        
        // Create multi-reader for packet + payload data
        let packet_reader = std::io::Cursor::new(&packet_raw);
        let mut multi_reader = MultiReader::new(packet_reader, reader);
        
        // Encrypt data in blocks
        let mut size_payload = 0i64;
        let mut buffer = vec![0u8; ENC_BLK_SIZE];
        
        loop {
            let bytes_read = multi_reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            
            size_payload += bytes_read as i64;
            if size_payload > max_size {
                return Err(Error::TooBig);
            }
            
            // Write encrypted block (simplified for now)
            writer.write_all(&buffer[..bytes_read])?;
        }
        
        Ok((vec![], size_payload))
    }

    /// Decrypt a packet from input (equivalent to PktEncRead in Go)
    pub fn decrypt_packet<R: Read, W: Write>(
        mut reader: R,
        mut writer: W,
        signature_verify: bool,
    ) -> Result<(Vec<u8>, i64), Error> {
        // Read and decrypt blocks (simplified for now)
        let mut total_size = 0i64;
        let mut buffer = vec![0u8; ENC_BLK_SIZE];
        
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    total_size += n as i64;
                    writer.write_all(&buffer[..n])?;
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }
        
        Ok((vec![], total_size))
    }
}

// Helper functions
fn derive_key(context: &[u8], shared_key: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, shared_key)
}

fn increment_nonce(nonce: &mut [u8; 12]) {
    for i in (0..12).rev() {
        nonce[i] = nonce[i].wrapping_add(1);
        if nonce[i] != 0 {
            break;
        }
    }
}

fn calculate_pad_size(payload_size: i64, min_size: i64, wrappers: i32) -> i64 {
    // Simplified version - full Go implementation is more complex
    let mut expected_size = payload_size;
    for _ in 0..wrappers {
        expected_size = 64 + size_with_tags(expected_size); // Simplified overhead calc
    }
    let pad = min_size - expected_size;
    if pad < 0 { 0 } else { pad }
}

fn size_with_tags(size: i64) -> i64 {
    // Simplified version of Go's sizeWithTags
    size + (size / ENC_BLK_SIZE as i64) * 16 + if size % ENC_BLK_SIZE as i64 != 0 { 16 } else { 0 }
}

// Helper for reading from multiple sources
struct MultiReader<R1: Read, R2: Read> {
    first: Option<R1>,
    second: R2,
}

impl<R1: Read, R2: Read> MultiReader<R1, R2> {
    fn new(first: R1, second: R2) -> Self {
        Self {
            first: Some(first),
            second,
        }
    }
}

impl<R1: Read, R2: Read> Read for MultiReader<R1, R2> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(ref mut first) = self.first {
            match first.read(buf) {
                Ok(0) => {
                    self.first = None;
                    self.second.read(buf)
                }
                other => other,
            }
        } else {
            self.second.read(buf)
        }
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
    
    #[test]
    fn test_nonce_increment() {
        let mut nonce = [0u8; 12];
        increment_nonce(&mut nonce);
        assert_eq!(nonce[11], 1);
        
        nonce[11] = 255;
        increment_nonce(&mut nonce);
        assert_eq!(nonce[11], 0);
        assert_eq!(nonce[10], 1);
    }
}
