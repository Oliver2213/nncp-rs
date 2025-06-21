//! Merkle Tree Hash implementation for NNCP
//!
//! This module provides a Merkle Tree Hash implementation compatible with the
//! original NNCP Go implementation. It uses BLAKE3 for hashing.

use blake3::{Hash, Hasher};
use std::io::{self, Read, Write};
use crate::constants::{MTH_SIZE, MTH_BLOCK_SIZE, MTH_LEAF_KEY, MTH_NODE_KEY};

/// MTH sequence entry (equivalent to Go's MTHSeqEnt)
#[derive(Debug, Clone)]
struct MTHSeqEnt {
    /// Level in the tree
    l: i32,
    /// Counter
    c: i64,
    /// Hash value
    h: [u8; MTH_SIZE],
}

impl MTHSeqEnt {
    fn new() -> Self {
        Self {
            l: 0,
            c: 0,
            h: [0; MTH_SIZE],
        }
    }
}

/// Merkle Tree Hash implementation (equivalent to Go's MTHSeq)
#[derive(Debug)]
pub struct MTH {
    /// Leaf key for hashing leaf nodes
    pub leaf_key: [u8; 32],
    /// Node key for hashing internal nodes
    pub node_key: [u8; 32],
    /// Leaf hasher
    hasher_leaf: Hasher,
    /// Node hasher  
    hasher_node: Hasher,
    /// Hash entries
    hashes: Vec<MTHSeqEnt>,
    /// Buffer for incomplete blocks
    buf: Vec<u8>,
    /// Counter
    ctr: i64,
    /// Size
    size: i64,
    /// Prepend size
    pub prepend_size: i64,
    /// Bytes to skip
    pub to_skip: i64,
    /// Whether we've finished
    finished: bool,
}

impl MTH {
    /// Create a new MTH with the given leaf and node keys
    pub fn new(leaf_key: [u8; 32], node_key: [u8; 32]) -> Self {
        Self {
            leaf_key,
            node_key,
            hasher_leaf: Hasher::new_keyed(&leaf_key),
            hasher_node: Hasher::new_keyed(&node_key),
            hashes: Vec::new(),
            buf: Vec::with_capacity(2 * MTH_BLOCK_SIZE),
            ctr: 0,
            size: 0,
            prepend_size: 0,
            to_skip: 0,
            finished: false,
        }
    }

    /// Create a new MTH with default keys (compatible with Go NNCP)
    pub fn default() -> Self {
        Self::new(MTH_LEAF_KEY, MTH_NODE_KEY)
    }

    /// Create MTH for given size and offset (equivalent to MTHSeqNew)
    pub fn new_seq(size: i64, offset: i64) -> Self {
        let mut mth = Self::default();
        
        if size == 0 {
            return mth;
        }
        
        let mut prepends = offset / MTH_BLOCK_SIZE as i64;
        let mut to_skip = MTH_BLOCK_SIZE as i64 - (offset - prepends * MTH_BLOCK_SIZE as i64);
        
        if to_skip == MTH_BLOCK_SIZE as i64 {
            to_skip = 0;
        } else if to_skip > 0 {
            prepends += 1;
        }
        
        let mut prepend_size = prepends * MTH_BLOCK_SIZE as i64;
        mth.ctr = prepends;
        
        if prepend_size > size {
            prepend_size = size;
        }
        
        if offset + to_skip > size {
            to_skip = size - offset;
        }
        
        mth.size = size;
        mth.prepend_size = prepend_size;
        mth.to_skip = to_skip;
        
        mth
    }

    /// Add data from the beginning of the file (equivalent to PreaddFrom)
    pub fn preadd_from<R: Read>(&mut self, reader: &mut R) -> io::Result<i64> {
        if self.finished {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "already finished"));
        }
        
        // Process existing buffer first if any (like Go does)
        if !self.buf.is_empty() {
            // Take up to MTH_BLOCK_SIZE from buffer
            let buf_data: Vec<u8> = if self.buf.len() >= MTH_BLOCK_SIZE {
                self.buf.drain(..MTH_BLOCK_SIZE).collect()
            } else {
                self.buf.drain(..).collect()
            };
            
            self.hasher_leaf.update(&buf_data);
            if buf_data.len() == MTH_BLOCK_SIZE {
                self.leaf_add();
                self.fold();
            } else {
                // Put incomplete block back
                self.buf.clear();
                self.buf.extend_from_slice(&buf_data);
            }
        }
        
        // Save current state
        let prev_hashes = self.hashes.clone();
        self.hashes.clear();
        let prev_ctr = self.ctr;
        self.ctr = 0;
        
        // Read prepend_size bytes
        let mut bytes_read = 0i64;
        let mut buffer = vec![0u8; MTH_BLOCK_SIZE];
        
        while bytes_read < self.prepend_size {
            let to_read = std::cmp::min(
                MTH_BLOCK_SIZE,
                (self.prepend_size - bytes_read) as usize
            );
            
            let n = reader.read(&mut buffer[..to_read])?;
            if n == 0 {
                break;
            }
            
            self.write(&buffer[..n])?;
            bytes_read += n as i64;
        }
        
        // Restore previous hashes
        for hash in prev_hashes {
            self.hashes.push(hash);
            self.fold();
        }
        
        // Restore counter state (like Go does)
        if !self.buf.is_empty() {
            self.ctr = prev_ctr - 1;
        } else {
            self.ctr = prev_ctr;
        }
        
        Ok(bytes_read)
    }

    /// Add a leaf to the hash tree
    fn leaf_add(&mut self) {
        let mut ent = MTHSeqEnt::new();
        ent.c = self.ctr;
        
        // Get the hash from the leaf hasher
        let hash = self.hasher_leaf.finalize();
        ent.h.copy_from_slice(hash.as_bytes());
        
        // Reset the hasher for next use
        self.hasher_leaf = Hasher::new_keyed(&self.leaf_key);
        
        self.hashes.push(ent);
        self.ctr += 1;
    }

    /// Fold hashes up the tree (equivalent to Go's fold function)
    fn fold(&mut self) {
        while self.hashes.len() >= 2 {
            let hlen = self.hashes.len();
            let end1_c = self.hashes[hlen - 2].c;
            let end0_l = self.hashes[hlen - 1].l;
            let end1_l = self.hashes[hlen - 2].l;
            
            // Check folding conditions from Go
            if end1_c % 2 == 1 {
                break;
            }
            if end1_l != end0_l {
                break;
            }
            
            // Get the hashes to combine
            let end1_h = self.hashes[hlen - 2].h;
            let end0_h = self.hashes[hlen - 1].h;
            
            // Hash them together
            self.hasher_node.update(&end1_h);
            self.hasher_node.update(&end0_h);
            let combined_hash = self.hasher_node.finalize();
            
            // Reset node hasher
            self.hasher_node = Hasher::new_keyed(&self.node_key);
            
            // Remove the last hash and update the second-to-last
            self.hashes.pop();
            let last_idx = self.hashes.len() - 1;
            self.hashes[last_idx].l += 1;
            self.hashes[last_idx].c /= 2;
            self.hashes[last_idx].h.copy_from_slice(combined_hash.as_bytes());
        }
    }

    /// Calculate the Merkle Tree Hash of a reader
    pub fn hash_reader<R: Read>(&mut self, reader: &mut R, chunk_size: usize) -> io::Result<Hash> {
        let mut buffer = vec![0; chunk_size];

        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            
            // Add data to buffer
            self.buf.extend_from_slice(&buffer[..n]);
            
            // Process complete blocks
            while self.buf.len() >= MTH_BLOCK_SIZE {
                let block: Vec<u8> = self.buf.drain(..MTH_BLOCK_SIZE).collect();
                self.hasher_leaf.update(&block);
                self.leaf_add();
                self.fold();
            }
        }

        // Get the final sum (equivalent to Go's Sum method)
        Ok(Hash::from_bytes(self.sum()))
    }

    /// Get the final sum (equivalent to Go's Sum method)
    pub fn sum(&mut self) -> [u8; MTH_SIZE] {
        if self.finished {
            return self.hashes[0].h;
        }
        
        // Handle remaining data in buffer
        if !self.buf.is_empty() {
            self.hasher_leaf.update(&self.buf);
            self.leaf_add();
            self.fold();
        }
        
        match self.ctr {
            0 => {
                // Empty case
                self.hasher_leaf.update(&[]);
                self.leaf_add();
                // Fall through to case 1
                self.handle_single_block();
            }
            1 => {
                // Single block case - need to duplicate and fold
                self.handle_single_block();
            }
            _ => {
                // Multiple blocks - force final folding
                self.force_final_fold();
            }
        }
        
        self.finished = true;
        self.hashes[0].h
    }
    
    /// Handle the special case of a single block (equivalent to Go's case 1 in Sum)
    fn handle_single_block(&mut self) {
        let mut ent = MTHSeqEnt::new();
        ent.c = 1;
        ent.h = self.hashes[0].h; // Copy the existing hash
        
        self.ctr = 2;
        self.hashes.push(ent);
        self.fold();
    }
    
    /// Force final folding for multiple blocks
    fn force_final_fold(&mut self) {
        while self.hashes.len() >= 2 {
            let hlen = self.hashes.len();
            // Adjust the last entry to match the second-to-last
            self.hashes[hlen - 1].l = self.hashes[hlen - 2].l;
            self.hashes[hlen - 1].c = self.hashes[hlen - 2].c + 1;
            self.fold();
        }
    }

    /// Calculate the Merkle Tree Hash of a slice
    pub fn hash_slice(&mut self, data: &[u8], chunk_size: usize) -> Hash {
        let mut cursor = std::io::Cursor::new(data);
        self.hash_reader(&mut cursor, chunk_size).unwrap()
    }

    /// Calculate the Merkle Tree Hash of a file
    pub fn hash_file(&mut self, path: &std::path::Path, chunk_size: usize) -> io::Result<Hash> {
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

impl Write for MTH {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "already finished"));
        }
        
        // Add data to buffer
        self.buf.extend_from_slice(buf);
        
        // Handle skip logic for seeking (like Go does)
        if self.to_skip > 0 {
            if (self.buf.len() as i64) < self.to_skip {
                return Ok(buf.len());
            }
            // Skip the specified bytes by removing from front of buffer
            let skip_amount = self.to_skip as usize;
            self.buf.drain(..skip_amount);
            self.to_skip = 0;
        }
        
        // Process complete blocks
        while self.buf.len() >= MTH_BLOCK_SIZE {
            let block: Vec<u8> = self.buf.drain(..MTH_BLOCK_SIZE).collect();
            self.hasher_leaf.update(&block);
            self.leaf_add();
            self.fold();
        }
        
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /* TODO: Fix these tests - they depend on methods that need to be implemented
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
    */
}
