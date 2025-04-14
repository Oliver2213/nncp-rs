//! Merkle Tree Hash implementation for NNCP
//!
//! This module provides a Merkle Tree Hash implementation compatible with the
//! original NNCP Go implementation. It uses BLAKE3 for hashing.

use blake3::{Hash, Hasher};
use std::io::{self, Read};
use crate::constants::MTH_SIZE;

/// Merkle Tree Hash implementation
#[derive(Debug, Clone)]
pub struct MTH {
    /// Leaf key for hashing leaf nodes
    leaf_key: [u8; 32],
    /// Node key for hashing internal nodes
    node_key: [u8; 32],
}

impl MTH {
    /// Create a new MTH with the given leaf and node keys
    pub fn new(leaf_key: [u8; 32], node_key: [u8; 32]) -> Self {
        Self { leaf_key, node_key }
    }

    /// Create a new MTH with default keys
    pub fn default() -> Self {
        // Create 32-byte arrays from the string literals
        let mut leaf_key = [0u8; 32];
        let mut node_key = [0u8; 32];
        
        // Copy the first 32 bytes from the literals
        leaf_key.copy_from_slice(&b"NNCPMTHLEAF................................"[..32]);
        node_key.copy_from_slice(&b"NNCPMTHNODE................................"[..32]);
        Self { leaf_key, node_key }
    }

    /// Hash a leaf node with the leaf key
    pub fn hash_leaf(&self, data: &[u8]) -> Hash {
        let mut hasher = Hasher::new_keyed(&self.leaf_key);
        hasher.update(data);
        hasher.finalize()
    }

    /// Hash an internal node with the node key
    pub fn hash_node(&self, left: &Hash, right: &Hash) -> Hash {
        let mut hasher = Hasher::new_keyed(&self.node_key);
        hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
        hasher.finalize()
    }

    /// Calculate the Merkle Tree Hash of a reader
    pub fn hash_reader<R: Read>(&self, reader: &mut R, chunk_size: usize) -> io::Result<Hash> {
        let mut buffer = vec![0; chunk_size];
        let mut hashes = Vec::new();

        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            let hash = self.hash_leaf(&buffer[..n]);
            hashes.push(hash);
        }

        if hashes.is_empty() {
            // Empty input case
            return Ok(self.hash_leaf(&[]));
        }

        // Build the Merkle tree
        while hashes.len() > 1 {
            let mut new_hashes = Vec::new();
            
            for i in (0..hashes.len()).step_by(2) {
                if i + 1 < hashes.len() {
                    // Hash pair of nodes
                    let hash = self.hash_node(&hashes[i], &hashes[i + 1]);
                    new_hashes.push(hash);
                } else {
                    // Odd number of hashes, promote the last one
                    new_hashes.push(hashes[i]);
                }
            }
            
            hashes = new_hashes;
        }

        Ok(hashes[0])
    }

    /// Calculate the Merkle Tree Hash of a slice
    pub fn hash_slice(&self, data: &[u8], chunk_size: usize) -> Hash {
        let mut cursor = std::io::Cursor::new(data);
        self.hash_reader(&mut cursor, chunk_size).unwrap()
    }

    /// Calculate the Merkle Tree Hash of a file
    pub fn hash_file(&self, path: &std::path::Path, chunk_size: usize) -> io::Result<Hash> {
        let mut file = std::fs::File::open(path)?;
        self.hash_reader(&mut file, chunk_size)
    }

    /// Convert a hash to a byte array
    pub fn hash_to_bytes(hash: &Hash) -> [u8; MTH_SIZE] {
        *hash.as_bytes()
    }

    /// Convert a byte array to a hash
    pub fn bytes_to_hash(bytes: &[u8; MTH_SIZE]) -> Hash {
        Hash::from_bytes(*bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_empty_hash() {
        let mth = MTH::default();
        let empty_hash = mth.hash_leaf(&[]);
        
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let reader_hash = mth.hash_reader(&mut cursor, 1024).unwrap();
        
        assert_eq!(empty_hash, reader_hash);
    }

    #[test]
    fn test_single_chunk_hash() {
        let mth = MTH::default();
        let data = b"Hello, world!";
        
        let leaf_hash = mth.hash_leaf(data);
        let slice_hash = mth.hash_slice(data, 1024);
        
        assert_eq!(leaf_hash, slice_hash);
    }

    #[test]
    fn test_multi_chunk_hash() {
        let mth = MTH::default();
        let data = vec![0u8; 4096]; // 4KB of zeros
        
        // Hash with 1KB chunks (should create a tree)
        let hash = mth.hash_slice(&data, 1024);
        
        // Manually calculate the expected hash
        let chunk1 = mth.hash_leaf(&data[0..1024]);
        let chunk2 = mth.hash_leaf(&data[1024..2048]);
        let chunk3 = mth.hash_leaf(&data[2048..3072]);
        let chunk4 = mth.hash_leaf(&data[3072..4096]);
        
        let node1 = mth.hash_node(&chunk1, &chunk2);
        let node2 = mth.hash_node(&chunk3, &chunk4);
        
        let expected = mth.hash_node(&node1, &node2);
        
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_odd_chunks() {
        let mth = MTH::default();
        let data = vec![0u8; 3072]; // 3KB of zeros
        
        // Hash with 1KB chunks (should create a tree with 3 leaves)
        let hash = mth.hash_slice(&data, 1024);
        
        // Manually calculate the expected hash
        let chunk1 = mth.hash_leaf(&data[0..1024]);
        let chunk2 = mth.hash_leaf(&data[1024..2048]);
        let chunk3 = mth.hash_leaf(&data[2048..3072]);
        
        let node1 = mth.hash_node(&chunk1, &chunk2);
        // In the case of odd number of nodes, the last one is promoted
        
        let expected = mth.hash_node(&node1, &chunk3);
        
        assert_eq!(hash, expected);
    }
}
