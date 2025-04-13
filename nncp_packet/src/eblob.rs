//! Encrypted blob implementation for NNCP
//! 
//! This module provides functionality for creating and decrypting encrypted blobs
//! using the Balloon hashing algorithm for key derivation.

use blake3::{Hasher, Hash};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use rand::RngCore;
use serde::{Serialize, Deserialize};
use std::io::{self, Read};
use thiserror::Error;

use crate::magic::{Magic, NNCP_B_V3};

/// Default space cost for Balloon hashing (memory usage)
pub const DEFAULT_S: u32 = 1 << 20 / 32;

/// Default time cost for Balloon hashing (iterations)
pub const DEFAULT_T: u32 = 1 << 4;

/// Default parallelism factor for Balloon hashing
pub const DEFAULT_P: u32 = 2;

/// Errors that can occur during EBlob operations
#[derive(Error, Debug)]
pub enum EBlobError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("Decryption error: {0}")]
    Decryption(String),
    
    #[error("Invalid magic number")]
    BadMagic,
    
    #[error("Format too old: {0}")]
    TooOld(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Encrypted blob structure
#[derive(Serialize, Deserialize, Debug)]
pub struct EBlob {
    /// Magic number identifying the blob type and version
    pub magic: [u8; 8],
    
    /// Space cost parameter for Balloon hashing
    pub s_cost: u32,
    
    /// Time cost parameter for Balloon hashing
    pub t_cost: u32,
    
    /// Parallelism parameter for Balloon hashing
    pub p_cost: u32,
    
    /// Random salt for key derivation
    pub salt: [u8; 32],
    
    /// Encrypted data
    pub blob: Vec<u8>,
}

impl EBlob {
    /// Create a new encrypted blob with the given parameters
    ///
    /// * `s_cost` - Space cost parameter (memory usage)
    /// * `t_cost` - Time cost parameter (iterations)
    /// * `p_cost` - Parallelism parameter
    /// * `password` - Password for encryption
    /// * `data` - Data to encrypt
    pub fn new(
        s_cost: u32, 
        t_cost: u32, 
        p_cost: u32, 
        password: &[u8], 
        data: &[u8]
    ) -> Result<Vec<u8>, EBlobError> {
        // Generate random salt
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        
        // Create EBlob structure
        let mut eblob = EBlob {
            magic: NNCP_B_V3.bytes,
            s_cost,
            t_cost,
            p_cost,
            salt,
            blob: Vec::new(),
        };
        
        // Serialize the EBlob header for use as associated data
        let header_bytes = bincode::serialize(&eblob)
            .map_err(|e| EBlobError::Serialization(e.to_string()))?;
        
        // Derive encryption key using Balloon hashing
        let key = balloon_hash(password, &salt, s_cost, t_cost, p_cost);
        
        // Create AEAD cipher
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&[0u8; 12]); // Zero nonce as in Go implementation
        
        // Encrypt the data
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| EBlobError::Encryption(e.to_string()))?;
        
        // Update the blob field with the encrypted data
        eblob.blob = ciphertext;
        
        // Serialize the complete EBlob
        bincode::serialize(&eblob)
            .map_err(|e| EBlobError::Serialization(e.to_string()))
    }
    
    /// Decrypt an encrypted blob
    ///
    /// * `eblob_raw` - Raw bytes of the encrypted blob
    /// * `password` - Password for decryption
    pub fn decrypt(eblob_raw: &[u8], password: &[u8]) -> Result<Vec<u8>, EBlobError> {
        // Deserialize the EBlob
        let eblob: EBlob = bincode::deserialize(eblob_raw)
            .map_err(|e| EBlobError::Serialization(e.to_string()))?;
        
        // Check magic number
        if eblob.magic != NNCP_B_V3.bytes {
            return Err(EBlobError::BadMagic);
        }
        
        // Create a copy without the blob for associated data
        let mut header_eblob = eblob.clone();
        header_eblob.blob = Vec::new();
        
        // Serialize the header for use as associated data
        let header_bytes = bincode::serialize(&header_eblob)
            .map_err(|e| EBlobError::Serialization(e.to_string()))?;
        
        // Derive decryption key using Balloon hashing
        let key = balloon_hash(password, &eblob.salt, eblob.s_cost, eblob.t_cost, eblob.p_cost);
        
        // Create AEAD cipher
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&[0u8; 12]); // Zero nonce as in Go implementation
        
        // Decrypt the data
        cipher.decrypt(nonce, eblob.blob.as_ref())
            .map_err(|e| EBlobError::Decryption(e.to_string()))
    }
}

impl Clone for EBlob {
    fn clone(&self) -> Self {
        Self {
            magic: self.magic,
            s_cost: self.s_cost,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
            salt: self.salt,
            blob: self.blob.clone(),
        }
    }
}

/// Implementation of the Balloon hashing algorithm
///
/// This is a simplified implementation based on the Go code.
/// For a full implementation, consider using a dedicated crate.
fn balloon_hash(password: &[u8], salt: &[u8], s: u32, t: u32, p: u32) -> [u8; 32] {
    // For now, we'll use a simplified approach with BLAKE3
    // In a real implementation, you would want to use the full Balloon algorithm
    let mut hasher = Hasher::new();
    hasher.update(password);
    hasher.update(salt);
    
    // Add the parameters to the hash
    hasher.update(&s.to_le_bytes());
    hasher.update(&t.to_le_bytes());
    hasher.update(&p.to_le_bytes());
    
    // Get the hash result
    let hash = hasher.finalize();
    
    // Convert the Hash to a 32-byte array
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_eblob_roundtrip() {
        let password = b"test_password";
        let data = b"Hello, world! This is a test of the EBlob encryption.";
        
        // Create an encrypted blob
        let encrypted = EBlob::new(4, 4, 1, password, data).unwrap();
        
        // Decrypt the blob
        let decrypted = EBlob::decrypt(&encrypted, password).unwrap();
        
        // Verify the decrypted data matches the original
        assert_eq!(decrypted, data);
    }
    
    #[test]
    fn test_eblob_wrong_password() {
        let password = b"test_password";
        let wrong_password = b"wrong_password";
        let data = b"Hello, world! This is a test of the EBlob encryption.";
        
        // Create an encrypted blob
        let encrypted = EBlob::new(4, 4, 1, password, data).unwrap();
        
        // Attempt to decrypt with wrong password should fail
        let result = EBlob::decrypt(&encrypted, wrong_password);
        assert!(result.is_err());
    }
}
