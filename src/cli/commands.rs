//! Subcommands

use clap::Parser;
use clap::Subcommand;
use nncp_rs::constants::{self, MTH_BLOCK_SIZE, NNCP_E_V6_MAGIC};
use nncp_rs::packet::{MTH, Hash, Packet, PacketType};
use nncp_rs::packet::encrypted::PktEnc;
use nncp_rs::magic::NNCP_P_V3;
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
    },
    /// Parse and display NNCP packet information
    #[command(name="pkt")]
    Pkt {
        /// Print packet overhead calculations
        #[arg(long, default_value_t = false)]
        overheads: bool,
        /// Write decrypted/parsed payload to stdout
        #[arg(long, default_value_t = false)]
        dump: bool,
        /// Try to zstd decompress dumped data
        #[arg(long, default_value_t = false)]
        decompress: bool,
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



/// Determine packet type and parse packet from stdin (equivalent to nncp-pkt main logic)
pub fn parse_packet(
    overheads: bool,
    dump: bool, 
    decompress: bool
) -> Result<(), Error> {
    if overheads {
        print_overheads()?;
        return Ok(());
    }

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    
    // Read initial bytes to determine packet type
    let mut magic_buf = [0u8; 8];
    if let Err(_) = read_full(&mut reader, &mut magic_buf) {
        return Err(anyhow::anyhow!("Unable to read magic number"));
    }

    // Check if it's an encrypted packet first
    if magic_buf == NNCP_E_V6_MAGIC {
        // Parse encrypted packet
        let mut remaining_header = vec![0u8; std::mem::size_of::<PktEnc>() - 8];
        read_full(&mut reader, &mut remaining_header)?;
        
        let mut full_header = Vec::new();
        full_header.extend_from_slice(&magic_buf);
        full_header.extend_from_slice(&remaining_header);
        
        if let Ok(enc_pkt) = try_parse_encrypted(&full_header) {
            print_encrypted_packet_info(&enc_pkt)?;
            
            if dump {
                // TODO: Implement decryption and payload dumping
                eprintln!("Warning: Decryption not yet implemented for encrypted packets");
                // For now, just read and dump remaining encrypted data
                let mut remaining_data = Vec::new();
                reader.read_to_end(&mut remaining_data)?;
                
                if decompress {
                    eprintln!("Warning: Cannot decompress encrypted payload without decryption");
                }
                io::stdout().write_all(&remaining_data)?;
            }
            return Ok(());
        }
    }
    
    // Check if it's a plain packet
    if magic_buf == NNCP_P_V3.bytes {
        // Create a reader that starts with the magic bytes we already read
        let mut all_data = Vec::new();
        all_data.extend_from_slice(&magic_buf);
        
        // Read the rest of the data
        reader.read_to_end(&mut all_data)?;
        
        // Try XDR deserialization first
        let mut cursor = std::io::Cursor::new(&all_data);
        if let Ok(packet) = serde_xdr::from_reader::<_, Packet>(&mut cursor) {
            print_plain_packet_info(&packet)?;
            
            if dump {
                // Dump remaining payload after packet header
                let remaining_data = &all_data[cursor.position() as usize..];
                dump_payload_data(remaining_data, decompress)?;
            }
            return Ok(());
        }
        
        // If XDR fails, try binary format
        cursor.set_position(0);
        if let Ok(packet) = Packet::decode(&mut cursor) {
            print_plain_packet_info(&packet)?;
            
            if dump {
                // Dump remaining payload after packet header
                let remaining_data = &all_data[cursor.position() as usize..];
                dump_payload_data(remaining_data, decompress)?;
            }
            return Ok(());
        }
        
        return Err(anyhow::anyhow!("Failed to parse plain packet with either XDR or binary format"));
    }

    Err(anyhow::anyhow!("Unable to determine packet type: unknown magic {:?}", 
                       hex::encode(&magic_buf)))
}

/// Read exactly the specified number of bytes (equivalent to io.ReadFull)
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<()> {
    let mut total_read = 0;
    while total_read < buf.len() {
        let n = reader.read(&mut buf[total_read..])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
        }
        total_read += n;
    }
    Ok(())
}

/// Try to parse buffer as encrypted packet
fn try_parse_encrypted(buf: &[u8]) -> Result<PktEnc, Error> {
    if buf.len() < 8 {
        return Err(anyhow::anyhow!("Buffer too short for magic"));
    }

    let magic: [u8; 8] = buf[..8].try_into().unwrap();
    if magic != NNCP_E_V6_MAGIC {
        return Err(anyhow::anyhow!("Invalid encrypted packet magic"));
    }

    // Deserialize the full encrypted packet header using XDR
    let mut cursor = std::io::Cursor::new(buf);
    serde_xdr::from_reader(&mut cursor)
        .map_err(|e| anyhow::anyhow!("Failed to parse encrypted packet: {}", e))
}

/// Try to parse buffer as plain packet
fn try_parse_plain<R: Read>(header_buf: &mut [u8], reader: &mut R) -> Result<Packet, Error> {
    if header_buf.len() < 11 {
        return Err(anyhow::anyhow!("Buffer too short for plain packet header"));
    }

    let magic: [u8; 8] = header_buf[..8].try_into().unwrap();
    if magic != NNCP_P_V3.bytes {
        return Err(anyhow::anyhow!("Invalid plain packet magic"));
    }

    let packet_type_byte = header_buf[8];
    let packet_type = PacketType::try_from(packet_type_byte)
        .map_err(|_| anyhow::anyhow!("Invalid packet type: {}", packet_type_byte))?;

    let nice = header_buf[9];
    let path_len = header_buf[10] as usize;

    // Read the path data
    let mut path = vec![0u8; path_len];
    if path_len > 0 {
        read_full(reader, &mut path)?;
    }

    // Create packet structure
    let mut packet = Packet::new(packet_type, nice, &path)?;
    packet.magic = magic;

    Ok(packet)
}

/// Print encrypted packet information
fn print_encrypted_packet_info(pkt: &PktEnc) -> Result<(), Error> {
    println!("Packet type: encrypted");
    println!("Niceness: {} ({})", Packet::format_niceness_value(pkt.nice), pkt.nice);
    println!("Sender: {}", base32::encode(base32::Alphabet::RFC4648 { padding: false }, &pkt.sender));
    println!("Recipient: {}", base32::encode(base32::Alphabet::RFC4648 { padding: false }, &pkt.recipient));
    println!("Exchange public key: {}", hex::encode(&pkt.exch_pub));
    println!("Signature: {}", hex::encode(&pkt.sign));
    Ok(())
}

/// Print plain packet information
fn print_plain_packet_info(pkt: &Packet) -> Result<(), Error> {
    println!("Packet type: {:?}", pkt.packet_type);
    println!("Niceness: {} ({})", pkt.format_niceness(), pkt.nice);
    println!("Path length: {}", pkt.path_len);
    
    if pkt.path_len > 0 {
        println!("Path: {}", pkt.format_path());
    }
    
    Ok(())
}

/// Print packet overhead calculations
fn print_overheads() -> Result<(), Error> {
    // Calculate plain packet overhead
    let dummy_path = b"dummy";
    let plain_pkt = Packet::new(PacketType::File, 160, dummy_path)?;
    let plain_overhead = plain_pkt.overhead()?;
    
    // Calculate encrypted packet overhead
    let dummy_sender = [0u8; 32];
    let dummy_recipient = [1u8; 32];
    let enc_overhead = Packet::enc_overhead(160, &dummy_sender, &dummy_recipient)?;
    
    // Calculate size overhead
    let size_overhead = Packet::size_overhead()?;
    
    println!("Plain: {}", plain_overhead);
    println!("Encrypted: {}", enc_overhead);
    println!("Size: {}", size_overhead);
    
    Ok(())
}

/// Dump payload data to stdout with optional decompression
fn dump_payload_data(data: &[u8], decompress: bool) -> Result<(), Error> {
    if decompress {
        // Decompress using zstd
        match zstd::bulk::decompress(data, 1024 * 1024 * 10) { // 10MB max
            Ok(decompressed) => {
                io::stdout().write_all(&decompressed)?;
            }
            Err(e) => {
                eprintln!("Warning: zstd decompression failed: {}, dumping raw data", e);
                io::stdout().write_all(data)?;
            }
        }
    } else {
        io::stdout().write_all(data)?;
    }
    Ok(())
}

/// Dump remaining payload to stdout
fn dump_remaining_payload<R: Read>(reader: &mut R, decompress: bool) -> Result<(), Error> {
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    dump_payload_data(&buffer, decompress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_niceness_formatting() {
        // Test Flash niceness range (0-63)
        assert_eq!(Packet::format_niceness_value(0), "F-32");
        assert_eq!(Packet::format_niceness_value(32), "F");
        assert_eq!(Packet::format_niceness_value(63), "F+31");
        
        // Test Priority niceness range (64-127)
        assert_eq!(Packet::format_niceness_value(64), "P-32");
        assert_eq!(Packet::format_niceness_value(96), "P");
        assert_eq!(Packet::format_niceness_value(127), "P+31");
        
        // Test Normal niceness range (128-191)
        assert_eq!(Packet::format_niceness_value(128), "N-32");
        assert_eq!(Packet::format_niceness_value(160), "N");
        assert_eq!(Packet::format_niceness_value(191), "N+31");
        
        // Test Bulk niceness range (192-254)
        assert_eq!(Packet::format_niceness_value(192), "B-32");
        assert_eq!(Packet::format_niceness_value(224), "B");
        assert_eq!(Packet::format_niceness_value(254), "B+30");
        
        // Test MAX niceness
        assert_eq!(Packet::format_niceness_value(255), "MAX");
    }

    #[test]
    fn test_path_formatting() {
        // Test file path formatting
        let file_path = b"/path/to/file.txt";
        assert_eq!(Packet::format_path_for_type(PacketType::File, file_path), "/path/to/file.txt");
        
        // Test exec command formatting with null bytes
        let exec_cmd = b"echo\x00hello\x00world";
        assert_eq!(Packet::format_path_for_type(PacketType::Exec, exec_cmd), "echo hello world");
        
        // Test 32-byte node ID for transit packets
        let node_id = [0u8; 32];
        let expected_base32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &node_id);
        assert_eq!(Packet::format_path_for_type(PacketType::Trns, &node_id), expected_base32);
        
        // Test shorter data for transit packets
        let short_data = b"short";
        assert_eq!(Packet::format_path_for_type(PacketType::Trns, short_data), hex::encode(short_data));
    }

    #[test]
    fn test_zstd_decompression() {
        // Test data
        let original_data = b"This is test data that will be compressed with zstd. ".repeat(10);
        
        // Compress the data
        let compressed_data = zstd::bulk::compress(&original_data, 3).unwrap();
        
        // Test decompression
        let decompressed_data = zstd::bulk::decompress(&compressed_data, 1024 * 1024).unwrap();
        
        assert_eq!(original_data, decompressed_data);
        
        // Test that compression actually reduced size
        assert!(compressed_data.len() < original_data.len());
    }
}