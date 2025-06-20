//! Encrypted packet implementation for NNCP
//!
//! This module provides functionality for encrypted packets compatible with the Go implementation.

use crate::packet::{Error, Packet};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, NewAead}};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use ed25519_compact::{Signature, PublicKey as Ed25519PublicKey};
use blake3;
use serde::{Serialize, Deserialize};
use std::io::{Read, Write};
use std::collections::HashMap;

const ENC_BLK_SIZE: usize = 128 * 1024; // 128KB blocks
const POLY1305_TAG_SIZE: usize = 16;

// Key derivation contexts (must match Go exactly)
const DERIVE_KEY_FULL_CTX: &str = "NNCPE\x00\x00\x06 FULL";
const DERIVE_KEY_SIZE_CTX: &str = "NNCPE\x00\x00\x06 SIZE"; 
const DERIVE_KEY_PAD_CTX: &str = "NNCPE\x00\x00\x06 PAD";

/// Node ID type (placeholder - should match your actual NodeID type)
pub type NodeID = [u8; 32];

/// Encrypted packet header (PktEnc in Go)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PktEnc {
    #[serde(with = "serde_bytes")]
    pub magic: [u8; 8],
    pub nice: u8,
    pub sender: NodeID,
    pub recipient: NodeID,
    #[serde(with = "serde_bytes")]
    pub exch_pub: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub sign: [u8; 64], // ed25519.SignatureSize
}

/// To-be-signed structure (PktTbs in Go)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PktTbs {
    #[serde(with = "serde_bytes")]
    pub magic: [u8; 8],
    pub nice: u8,
    pub sender: NodeID,
    pub recipient: NodeID,
    #[serde(with = "serde_bytes")]
    pub exch_pub: [u8; 32],
}

/// Packet size information (PktSize in Go)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PktSize {
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
        // Generate ephemeral keypair (equivalent to box.GenerateKey)
        let ephemeral_secret = EphemeralSecret::new(rand::thread_rng());
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        
        // Serialize the packet using XDR (equivalent to xdr.Marshal(&buf, pkt))
        let mut packet_raw = Vec::new();
        serde_xdr::to_writer(&mut packet_raw, packet)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        
        // Create TBS (to-be-signed) structure
        let tbs = PktTbs {
            magic: [b'N', b'N', b'C', b'P', b'E', 0, 0, 6], // MagicNNCPEv6
            nice,
            sender: [0u8; 32], // Placeholder - needs actual node ID
            recipient: [0u8; 32], // Placeholder - needs actual node ID
            exch_pub: ephemeral_public.to_bytes(),
        };
        
        // Serialize TBS using XDR
        let mut tbs_raw = Vec::new();
        serde_xdr::to_writer(&mut tbs_raw, &tbs)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        
        // Create packet header (signature placeholder for now)
        let pkt_enc = PktEnc {
            magic: [b'N', b'N', b'C', b'P', b'E', 0, 0, 6],
            nice,
            sender: [0u8; 32], // Placeholder
            recipient: [0u8; 32], // Placeholder
            exch_pub: ephemeral_public.to_bytes(),
            sign: [0u8; 64], // Placeholder signature
        };
        
        // Serialize and write header using XDR
        let mut pkt_enc_raw = Vec::new();
        serde_xdr::to_writer(&mut pkt_enc_raw, &pkt_enc)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        writer.write_all(&pkt_enc_raw)?;
        
        // Derive shared key (placeholder - needs actual key exchange)
        let shared_key = [0u8; 32]; // Placeholder
        
        // Derive encryption keys using BLAKE3 (equivalent to blake3.DeriveKey)
        let key_full = blake3::derive_key(DERIVE_KEY_FULL_CTX, &shared_key);
        let key_size = blake3::derive_key(DERIVE_KEY_SIZE_CTX, &shared_key);
        
        let aead_full = ChaCha20Poly1305::new(&Key::from_slice(&key_full));
        let aead_size = ChaCha20Poly1305::new(&Key::from_slice(&key_size));
        
        // Associated data for AEAD (equivalent to blake3.Sum256)
        let ad = blake3::hash(&tbs_raw);
        
        // Initialize nonce
        let mut nonce_bytes = [0u8; 12];
        
        // Create multi-reader for packet + payload data (equivalent to io.MultiReader)
        let packet_reader = std::io::Cursor::new(&packet_raw);
        let mut multi_reader = MultiReader::new(packet_reader, reader);
        
        // Encrypt data in blocks
        let mut size_payload = 0i64;
        let mut data = vec![0u8; ENC_BLK_SIZE];
        
        // Read and encrypt full blocks
        loop {
            let n = multi_reader.read(&mut data)?;
            if n == 0 {
                break;
            }
            
            size_payload += n as i64;
            if size_payload > max_size {
                return Err(Error::TooBig);
            }
            
            if n == ENC_BLK_SIZE {
                // Full block - encrypt with aeadFull
                let nonce = Nonce::from_slice(&nonce_bytes);
                let ct = aead_full.encrypt(nonce, &data[..n])
                    .map_err(|_| Error::Encryption("ChaCha20Poly1305 encryption failed".to_string()))?;
                writer.write_all(&ct)?;
                ctr_incr(&mut nonce_bytes);
            } else {
                // Last partial block - handle size info
                break;
            }
        }
        
        // Handle final block with size information
        let size_pad = size_pad_calc(size_payload, min_size, wrappers);
        let pkt_size = PktSize {
            payload: size_payload as u64,
            pad: size_pad as u64,
        };
        
        // Serialize size info using XDR
        let mut size_raw = Vec::new();
        serde_xdr::to_writer(&mut size_raw, &pkt_size)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        let pkt_size_overhead = size_raw.len();
        
        // Complex final block logic from Go
        let n = data.len(); // Last read size
        let aead_last = if n + pkt_size_overhead > ENC_BLK_SIZE {
            // Size info + data exceeds block size - split across blocks
            let left_size = (n + pkt_size_overhead) - ENC_BLK_SIZE;
            let mut left = vec![0u8; left_size];
            left.copy_from_slice(&data[n - left_size..n]);
            
            // First block: size info + partial data
            data[pkt_size_overhead..].copy_from_slice(&data[..n - left_size]);
            data[..pkt_size_overhead].copy_from_slice(&size_raw);
            
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ct = aead_size.encrypt(nonce, &data[..ENC_BLK_SIZE])
                .map_err(|_| Error::Encryption("Size block encryption failed".to_string()))?;
            writer.write_all(&ct)?;
            ctr_incr(&mut nonce_bytes);
            
            // Prepare remaining data
            data[..left_size].copy_from_slice(&left);
            data.truncate(left_size);
            &aead_full
        } else {
            // Size info + data fits in one block
            data[pkt_size_overhead..pkt_size_overhead + n].copy_from_slice(&data[..n]);
            data[..pkt_size_overhead].copy_from_slice(&size_raw);
            data.truncate(n + pkt_size_overhead);
            &aead_size
        };
        
        // Add padding to current block
        let current_size = data.len();
        let size_block_padded = if size_pad > (ENC_BLK_SIZE as i64 - current_size as i64) {
            ENC_BLK_SIZE
        } else {
            current_size + size_pad as usize
        };
        
        // Zero-pad the block
        data.resize(size_block_padded, 0);
        
        // Encrypt final block
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = aead_last.encrypt(nonce, &data)
            .map_err(|_| Error::Encryption("Final block encryption failed".to_string()))?;
        writer.write_all(&ct)?;
        
        // Handle remaining padding if any
        let size_pad_left = size_pad - (size_block_padded as i64 - current_size as i64);
        if size_pad_left > 0 {
            let key_pad = blake3::derive_key(DERIVE_KEY_PAD_CTX, &shared_key);
            let mut hasher = blake3::Hasher::new_keyed(&key_pad);
            let mut xof = hasher.finalize_xof();
            
            // Stream padding data
            let mut remaining = size_pad_left;
            let mut pad_buffer = vec![0u8; 8192];
            while remaining > 0 {
                let chunk_size = std::cmp::min(remaining as usize, pad_buffer.len());
                xof.fill(&mut pad_buffer[..chunk_size]);
                writer.write_all(&pad_buffer[..chunk_size])?;
                remaining -= chunk_size as i64;
            }
        }
        
        Ok((pkt_enc_raw, size_payload))
    }

    /// Decrypt a packet from input (equivalent to PktEncRead in Go)
    pub fn decrypt_packet<R: Read, W: Write>(
        mut reader: R,
        mut writer: W,
        signature_verify: bool,
        shared_key_cached: Option<&[u8]>,
    ) -> Result<(Vec<u8>, i64), Error> {
        // Read and deserialize header using XDR
        let pkt_enc: PktEnc = serde_xdr::from_reader(&mut reader)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        
        // Verify magic number
        if pkt_enc.magic != [b'N', b'N', b'C', b'P', b'E', 0, 0, 6] {
            return Err(Error::BadMagic);
        }
        
        // Prepare TBS for signature verification
        let tbs = PktTbs {
            magic: pkt_enc.magic,
            nice: pkt_enc.nice,
            sender: pkt_enc.sender,
            recipient: pkt_enc.recipient,
            exch_pub: pkt_enc.exch_pub,
        };
        
        let mut tbs_raw = Vec::new();
        serde_xdr::to_writer(&mut tbs_raw, &tbs)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        
        // Associated data
        let ad = blake3::hash(&tbs_raw);
        
        // Derive shared key (placeholder for now)
        let shared_key = if let Some(cached) = shared_key_cached {
            cached.to_vec()
        } else {
            vec![0u8; 32] // Placeholder
        };
        
        // Derive decryption keys
        let key_full = blake3::derive_key(DERIVE_KEY_FULL_CTX, &shared_key);
        let key_size = blake3::derive_key(DERIVE_KEY_SIZE_CTX, &shared_key);
        
        let aead_full = ChaCha20Poly1305::new(&Key::from_slice(&key_full));
        let aead_size = ChaCha20Poly1305::new(&Key::from_slice(&key_size));
        
        // Initialize nonce
        let mut nonce_bytes = [0u8; 12];
        
        // Decrypt full blocks
        let mut size = 0i64;
        let mut ct = vec![0u8; ENC_BLK_SIZE + POLY1305_TAG_SIZE];
        let mut pt = vec![0u8; ENC_BLK_SIZE];
        
        // Read full blocks
        loop {
            match reader.read(&mut ct) {
                Ok(n) if n == ENC_BLK_SIZE + POLY1305_TAG_SIZE => {
                    // Full encrypted block
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    let plaintext = aead_full.decrypt(nonce, &ct[..n])
                        .map_err(|_| Error::Decryption("Full block decryption failed".to_string()))?;
                    
                    size += ENC_BLK_SIZE as i64;
                    writer.write_all(&plaintext)?;
                    ctr_incr(&mut nonce_bytes);
                }
                Ok(n) if n > POLY1305_TAG_SIZE => {
                    // Final block with size info
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    let mut plaintext = aead_size.decrypt(nonce, &ct[..n])
                        .map_err(|_| Error::Decryption("Size block decryption failed".to_string()))?;
                    
                    // Extract size info
                    let pkt_size: PktSize = serde_xdr::from_bytes(&plaintext)
                        .map_err(|e| Error::Serialization(e.to_string()))?;
                    
                    // Calculate size overhead and extract remaining data
                    let mut size_overhead_buf = Vec::new();
                    serde_xdr::to_writer(&mut size_overhead_buf, &pkt_size)
                        .map_err(|e| Error::Serialization(e.to_string()))?;
                    let pkt_size_overhead = size_overhead_buf.len();
                    
                    plaintext.drain(..pkt_size_overhead);
                    
                    // Process remaining payload
                    let left = pkt_size.payload as i64 - size;
                    let mut remaining_left = left;
                    
                    // Write data from current block
                    while remaining_left > plaintext.len() as i64 {
                        size += plaintext.len() as i64;
                        remaining_left -= plaintext.len() as i64;
                        writer.write_all(&plaintext)?;
                        
                        // Read next block
                        let n = reader.read(&mut ct)?;
                        if n == 0 {
                            return Err(Error::Decryption("Unexpected EOF".to_string()));
                        }
                        
                        ctr_incr(&mut nonce_bytes);
                        let nonce = Nonce::from_slice(&nonce_bytes);
                        plaintext = aead_full.decrypt(nonce, &ct[..n])
                            .map_err(|_| Error::Decryption("Continuation block decryption failed".to_string()))?;
                    }
                    
                    // Write final payload data
                    size += remaining_left;
                    writer.write_all(&plaintext[..remaining_left as usize])?;
                    plaintext.drain(..remaining_left as usize);
                    
                    // Verify padding in current block
                    if pkt_size.pad < plaintext.len() as u64 {
                        return Err(Error::Decryption("Unexpected pad".to_string()));
                    }
                    
                    for &byte in &plaintext {
                        if byte != 0 {
                            return Err(Error::Decryption("Non-zero pad byte".to_string()));
                        }
                    }
                    
                    // Verify remaining padding
                    let size_pad_left = pkt_size.pad as i64 - plaintext.len() as i64;
                    if size_pad_left > 0 {
                        verify_padding(&mut reader, &shared_key, size_pad_left)?;
                    }
                    
                    break;
                }
                Ok(_) => {
                    return Err(Error::Decryption("Invalid block size".to_string()));
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }
        
        Ok((shared_key, size))
    }
}

// Helper functions matching Go implementation

/// Increment counter (equivalent to ctrIncr in Go)
fn ctr_incr(nonce: &mut [u8; 12]) {
    for i in (0..12).rev() {
        nonce[i] = nonce[i].wrapping_add(1);
        if nonce[i] != 0 {
            return;
        }
    }
    panic!("counter overflow");
}

/// Calculate size with authentication tags (equivalent to sizeWithTags in Go)
fn size_with_tags(size: i64) -> i64 {
    let pkt_size_overhead = 16i64; // Simplified - should calculate actual XDR overhead
    let mut full_size = size + pkt_size_overhead;
    full_size += (size / ENC_BLK_SIZE as i64) * POLY1305_TAG_SIZE as i64;
    if size % ENC_BLK_SIZE as i64 != 0 {
        full_size += POLY1305_TAG_SIZE as i64;
    }
    full_size
}

/// Calculate padding size (equivalent to sizePadCalc in Go)
fn size_pad_calc(size_payload: i64, min_size: i64, wrappers: i32) -> i64 {
    let pkt_overhead = 11i64; // Simplified - should calculate actual packet overhead
    let pkt_enc_overhead = 120i64; // Simplified - should calculate actual encrypted packet overhead
    
    let mut expected_size = size_payload - pkt_overhead;
    for _ in 0..wrappers {
        expected_size = pkt_enc_overhead + size_with_tags(pkt_overhead + expected_size);
    }
    let size_pad = min_size - expected_size;
    if size_pad < 0 { 0 } else { size_pad }
}

/// Verify padding (equivalent to padding verification in Go)
fn verify_padding<R: Read>(reader: &mut R, shared_key: &[u8], size_pad: i64) -> Result<(), Error> {
    let key_pad = blake3::derive_key(DERIVE_KEY_PAD_CTX, shared_key);
    let mut hasher = blake3::Hasher::new_keyed(&key_pad);
    let mut xof = hasher.finalize_xof();
    
    let mut expected = vec![0u8; 8192];
    let mut actual = vec![0u8; 8192];
    let mut remaining = size_pad;
    
    while remaining > 0 {
        let chunk_size = std::cmp::min(remaining as usize, expected.len());
        xof.fill(&mut expected[..chunk_size]);
        reader.read_exact(&mut actual[..chunk_size])?;
        
        if expected[..chunk_size] != actual[..chunk_size] {
            return Err(Error::Decryption("Wrong pad value".to_string()));
        }
        
        remaining -= chunk_size as i64;
    }
    
    if remaining < 0 {
        return Err(Error::Decryption("Excess pad".to_string()));
    }
    
    Ok(())
}

// Helper for reading from multiple sources (equivalent to io.MultiReader)
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
    fn test_ctr_incr() {
        let mut nonce = [0u8; 12];
        ctr_incr(&mut nonce);
        assert_eq!(nonce[11], 1);
        
        nonce[11] = 255;
        ctr_incr(&mut nonce);
        assert_eq!(nonce[11], 0);
        assert_eq!(nonce[10], 1);
    }
    
    #[test]
    fn test_size_with_tags() {
        let size = ENC_BLK_SIZE as i64;
        let result = size_with_tags(size);
        assert!(result > size);
    }
}
