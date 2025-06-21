//! Subcommands

use clap::Parser;
use clap::Subcommand;
use nncp_rs::constants::{self, MTH_BLOCK_SIZE};
use nncp_rs::packet::{MTH, Hash};
use std::path::PathBuf;
use std::io::{self, BufReader, Read, Seek, Write};
use anyhow::Error;

#[derive(Subcommand)]
#[deny(missing_docs)]
/// all NNCP subcommands
pub enum Commands {
    /// Generates a node and prints it's base 32 encoded keys
    #[command(name="gen-node")]
    GenerateNode,
    /// Prints your local node's ID
    #[command(name="print-id")]
    PrintLocalNode {
        /// Include an emoji representation of the ID
        #[arg(short, long, default_value_t=false)]
        emojify: bool,
    },
    /// Calculate MTH hash of a file
    #[command(name="hash")]
    Hash {
        /// Read the file instead of stdin
        #[arg(short = 'f', long = "file")]
        file: Option<PathBuf>,
        /// Seek the file, hash, rewind, hash remaining
        #[arg(long, default_value_t = 0)]
        seek: u64,
        /// Force MTHFat implementation usage
        #[arg(long = "force-fat", default_value_t = false)]
        force_fat: bool,
        /// Progress showing
        #[arg(long, default_value_t = false)]
        progress: bool,
        /// Print MTH steps calculations
        #[arg(long, default_value_t = false)]
        debug: bool,
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = &constants::LONG_ABOUT)]
#[command(propagate_version = true)]
/// Our command-line interface
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    /// NNCP configuration file
    /// Defaults to a local os-specific directory
    #[arg(short, long, value_name = "CONFIG_FILE", env="NNCP_RS_CONFIG")]
    pub config: Option<PathBuf>,
    /// Path to our ongoing log file
    #[arg(short, long, value_name="LOG_FILE", env="NNCP_RS_LOG_FILE")]
    pub log: Option<PathBuf>,
    /// Our node's spool directory, to store incoming and outgoing packets
    #[arg(short, long, env="NNCP_RS_SPOOL_DIR")]
    pub spool_directory: Option<PathBuf>,
}

/// Calculate MTH hash of a file (equivalent to nncp-hash)
pub fn hash_file(
    file: &Option<PathBuf>, 
    seek: u64, 
    force_fat: bool, 
    progress: bool, 
    debug: bool
) -> Result<(), Error> {
    let mut mth = MTH::default();
    
    if debug {
        println!("Leaf BLAKE3 key: {}", hex::encode(&mth.leaf_key));
        println!("Node BLAKE3 key: {}", hex::encode(&mth.node_key));
    }
    
    // Get file size for progress tracking
    let mut size = 0i64;
    let mut reader: Box<dyn Read> = if let Some(path) = file {
        let file_handle = std::fs::File::open(path)?;
        size = file_handle.metadata()?.len() as i64;
        Box::new(BufReader::new(file_handle))
    } else {
        // Reading from stdin, disable progress
        if progress {
            eprintln!("Progress disabled when reading from stdin");
        }
        Box::new(BufReader::new(io::stdin()))
    };
    
    // Handle seek if specified  
    if seek > 0 {
        if file.is_none() {
            return Err(anyhow::anyhow!("--file is required with --seek"));
        }
        
        // Get file path for seeking logic
        let file_path = file.as_ref().unwrap();
        
        // Get file size for MTH initialization
        let file_handle = std::fs::File::open(file_path)?;
        let file_size = file_handle.metadata()?.len() as i64;
        drop(file_handle);
        
        // Create MTH with seek parameters (size, offset)
        let mut mth = MTH::new_seq(file_size, seek as i64);
        
        if debug {
            println!("Leaf BLAKE3 key: {}", hex::encode(&mth.leaf_key));
            println!("Node BLAKE3 key: {}", hex::encode(&mth.node_key));
            println!("Size: {}, Offset: {}", file_size, seek);
            println!("PrependSize: {}, ToSkip: {}", mth.prepend_size, mth.to_skip);
        }
        
        // First, read from the seek position to EOF (like Go does)
        let mut file_handle = std::fs::File::open(file_path)?;
        file_handle.seek(std::io::SeekFrom::Start(seek))?;
        let mut reader = BufReader::new(file_handle);
        
        // Read from seek position using Write trait (like Go CopyProgressed does)
        let mut buffer = vec![0u8; MTH_BLOCK_SIZE];
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            mth.write(&buffer[..n])?;
        }
        
        // Then add prepended data from beginning of file
        let mut file_handle = std::fs::File::open(file_path)?;
        let mut reader = BufReader::new(file_handle);
        mth.preadd_from(&mut reader)?;
        
        // Get final hash
        let hash = Hash::from_bytes(mth.sum());
        println!("{}", hex::encode(hash.as_bytes()));
        
        return Ok(());
    }
    
    // Calculate the hash
    let hash = if force_fat {
        // For now, we don't distinguish between fat and regular MTH
        // The Go version has MTHFat for different performance characteristics
        mth.hash_reader(&mut reader, MTH_BLOCK_SIZE)?
    } else {
        mth.hash_reader(&mut reader, MTH_BLOCK_SIZE)?
    };
    
    // Print the result as hex
    println!("{}", hex::encode(hash.as_bytes()));
    
    Ok(())
}