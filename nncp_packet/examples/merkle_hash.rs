//! Example showing how to use the Merkle Tree Hash implementation

use nncp_packet::MTH;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a default MTH instance
    let mth = MTH::default();
    
    // Hash a simple string
    let data = b"Hello, world!";
    let hash = mth.hash_slice(data, 1024);
    println!("Hash of 'Hello, world!': {:?}", hash);
    
    // Hash a file if it exists
    let file_path = Path::new("Cargo.toml");
    if file_path.exists() {
        let hash = mth.hash_file(file_path, 1024)?;
        println!("Hash of {}: {:?}", file_path.display(), hash);
    }
    
    // Create a larger data set and hash it
    let large_data = vec![0u8; 1024 * 1024]; // 1MB of zeros
    let hash = mth.hash_slice(&large_data, 1024);
    println!("Hash of 1MB of zeros: {:?}", hash);
    
    // Demonstrate hashing a reader
    let data = b"This is some data to hash";
    let mut reader = BufReader::new(data.as_slice());
    let hash = mth.hash_reader(&mut reader, 1024)?;
    println!("Hash from reader: {:?}", hash);
    
    Ok(())
}
