//! nncp-stat command implementation

use nncp_rs::constants::NNCP_E_V6_MAGIC;
use nncp_rs::packet::Packet;
use nncp_rs::packet::encrypted::PktEnc;
use nncp_rs::magic::NNCP_P_V3;
use nncp_rs::nncp::NodeID;
use crate::cli::Context;
use std::io::{self, Read};
use std::collections::HashMap;
use std::fs;
use anyhow::Error;
use bytesize::ByteSize;

/// Statistics for packets of a specific niceness level
#[derive(Debug, Clone, Default)]
struct NicenessStats {
    count: u64,
    total_size: u64,
}

/// Statistics for a node's queue
#[derive(Debug, Clone, Default)]
struct NodeStats {
    rx: HashMap<u8, NicenessStats>,
    tx: HashMap<u8, NicenessStats>,
}

/// Show queue statistics (equivalent to nncp-stat)
pub fn show_statistics(ctx: Context, filter_node: Option<&str>, show_packets: bool) -> Result<(), Error> {
    let spool_path = &ctx.spool_path;
    
    if !spool_path.exists() {
        return Err(anyhow::anyhow!("Spool directory does not exist: {}", spool_path.display()));
    }
    
    let mut all_stats: HashMap<NodeID, NodeStats> = HashMap::new();
    let mut node_names: HashMap<NodeID, String> = HashMap::new();
    
    // Build reverse lookup from NodeID to friendly name
    for (name, node_id) in &ctx.neighbor_aliases {
        node_names.insert(*node_id, name.clone());
    }
    
    // If filtering by node, resolve the name to NodeID
    let filter_node_id = if let Some(name) = filter_node {
        match ctx.neighbor_aliases.get(name) {
            Some(id) => Some(*id),
            None => {
                // Try to decode as base32 NodeID
                match base32::decode(base32::Alphabet::RFC4648 { padding: false }, name) {
                    Some(bytes) if bytes.len() == 32 => {
                        let mut node_id = [0u8; 32];
                        node_id.copy_from_slice(&bytes);
                        Some(node_id)
                    }
                    _ => return Err(anyhow::anyhow!("Unknown node: {}", name)),
                }
            }
        }
    } else {
        None
    };
    
    // Scan spool directory for node directories
    for entry in fs::read_dir(spool_path)? {
        let entry = entry?;
        let path = entry.path();
        
        if !path.is_dir() {
            continue;
        }
        
        // Parse directory name as NodeID (should be base32 encoded)
        let dir_name = match path.file_name().and_then(|s| s.to_str()) {
            Some(name) => name,
            None => continue,
        };
        
        let node_id = match base32::decode(base32::Alphabet::RFC4648 { padding: false }, dir_name) {
            Some(bytes) if bytes.len() == 32 => {
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                id
            }
            _ => continue, // Skip invalid node directories
        };
        
        // If filtering, skip nodes that don't match
        if let Some(filter_id) = filter_node_id {
            if node_id != filter_id {
                continue;
            }
        }
        
        let mut node_stats = NodeStats::default();
        
        // Scan rx directory
        let rx_path = path.join("rx");
        if rx_path.exists() {
            scan_packet_directory(&rx_path, &mut node_stats.rx, show_packets, "rx", &node_id, &node_names)?;
        }
        
        // Scan tx directory  
        let tx_path = path.join("tx");
        if tx_path.exists() {
            scan_packet_directory(&tx_path, &mut node_stats.tx, show_packets, "tx", &node_id, &node_names)?;
        }
        
        all_stats.insert(node_id, node_stats);
    }
    
    // Display results
    if show_packets {
        // Individual packet listing was already printed during scan
        return Ok(());
    }
    
    // Summary statistics
    if all_stats.is_empty() {
        println!("No queued packets found.");
        return Ok(());
    }
    
    println!("{:<20} {:<10} {:<15} {:<15}", "Node", "Niceness", "Rx", "Tx");
    println!("{}", "-".repeat(60));
    
    for (node_id, stats) in &all_stats {
        let node_name = node_names.get(node_id)
            .cloned()
            .unwrap_or_else(|| base32::encode(base32::Alphabet::RFC4648 { padding: false }, node_id));
        
        // Collect all niceness levels present for this node
        let mut niceness_levels: std::collections::BTreeSet<u8> = std::collections::BTreeSet::new();
        for nice in stats.rx.keys() {
            niceness_levels.insert(*nice);
        }
        for nice in stats.tx.keys() {
            niceness_levels.insert(*nice);
        }
        
        if niceness_levels.is_empty() {
            continue;
        }
        
        for niceness in niceness_levels {
            let default_stats = NicenessStats::default();
            let rx_stats = stats.rx.get(&niceness).unwrap_or(&default_stats);
            let tx_stats = stats.tx.get(&niceness).unwrap_or(&default_stats);
            
            let rx_display = if rx_stats.count > 0 {
                format!("{} ({})", rx_stats.count, ByteSize::b(rx_stats.total_size))
            } else {
                "0".to_string()
            };
            
            let tx_display = if tx_stats.count > 0 {
                format!("{} ({})", tx_stats.count, ByteSize::b(tx_stats.total_size))
            } else {
                "0".to_string()
            };
            
            println!("{:<20} {:<10} {:<15} {:<15}", 
                     node_name, 
                     Packet::format_niceness_value(niceness),
                     rx_display,
                     tx_display);
        }
    }
    
    Ok(())
}

/// Scan a packet directory (rx or tx) and collect statistics
fn scan_packet_directory(
    dir_path: &std::path::Path,
    stats: &mut HashMap<u8, NicenessStats>,
    show_packets: bool,
    dir_type: &str,
    node_id: &NodeID,
    node_names: &HashMap<NodeID, String>,
) -> Result<(), Error> {
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        
        if !path.is_file() {
            continue;
        }
        
        // Skip partial (.part) and no-check (.nock) files for now
        // TODO: Add support for these in the future
        let file_name = match path.file_name().and_then(|s| s.to_str()) {
            Some(name) => name,
            None => continue,
        };
        
        if file_name.ends_with(".part") || file_name.ends_with(".nock") {
            continue;
        }
        
        // Try to read packet header to get niceness and size
        match read_packet_info(&path) {
            Ok((niceness, size)) => {
                let entry = stats.entry(niceness).or_default();
                entry.count += 1;
                entry.total_size += size;
                
                if show_packets {
                    let node_name = node_names.get(node_id)
                        .cloned()
                        .unwrap_or_else(|| base32::encode(base32::Alphabet::RFC4648 { padding: false }, node_id));
                    
                    println!("{} {} {} {} {}", 
                             node_name,
                             dir_type,
                             Packet::format_niceness_value(niceness),
                             ByteSize::b(size),
                             file_name);
                }
            }
            Err(_) => {
                // Skip files we can't parse
                continue;
            }
        }
    }
    
    Ok(())
}

/// Read packet header to extract niceness and size information
fn read_packet_info(file_path: &std::path::Path) -> Result<(u8, u64), Error> {
    let mut file = fs::File::open(file_path)?;
    let file_size = file.metadata()?.len();
    
    // Read initial bytes to determine packet type
    let mut magic_buf = [0u8; 8];
    if let Err(_) = read_full(&mut file, &mut magic_buf) {
        return Err(anyhow::anyhow!("Unable to read magic number"));
    }
    
    // Check if it's an encrypted packet
    if magic_buf == NNCP_E_V6_MAGIC {
        // Read the rest of the encrypted packet header
        let mut remaining_header = vec![0u8; std::mem::size_of::<PktEnc>() - 8];
        read_full(&mut file, &mut remaining_header)?;
        
        let mut full_header = Vec::new();
        full_header.extend_from_slice(&magic_buf);
        full_header.extend_from_slice(&remaining_header);
        
        let enc_pkt = try_parse_encrypted(&full_header)?;
        return Ok((enc_pkt.nice, file_size));
    }
    
    // Check if it's a plain packet
    if magic_buf == NNCP_P_V3.bytes {
        // Read packet type and niceness
        let mut packet_info = [0u8; 2];
        read_full(&mut file, &mut packet_info)?;
        
        let _packet_type = packet_info[0];
        let niceness = packet_info[1];
        
        return Ok((niceness, file_size));
    }
    
    Err(anyhow::anyhow!("Unknown packet format"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use nncp_rs::packet::PacketType;

    #[test]
    fn test_read_packet_info() {
        // Create a test plain packet
        let packet = Packet::new(PacketType::File, 160, b"/test/file.txt").unwrap();
        
        // Write packet to temporary file in /tmp
        let temp_path = format!("/tmp/test_packet_{}", std::process::id());
        let mut temp_file = fs::File::create(&temp_path).unwrap();
        packet.encode(&mut temp_file).unwrap();
        
        // Test reading packet info
        let (niceness, size) = read_packet_info(std::path::Path::new(&temp_path)).unwrap();
        assert_eq!(niceness, 160);
        assert!(size > 0);
        
        // Clean up
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_show_statistics_empty_spool() {
        // Create temporary spool directory in /tmp
        let temp_dir = format!("/tmp/test_spool_{}", std::process::id());
        fs::create_dir_all(&temp_dir).unwrap();
        
        let mut ctx = Context::new(
            format!("{}/config", temp_dir),
            format!("{}/log", temp_dir), 
            &temp_dir,
        );
        // Allow config load to fail for tests
        let _ = ctx.load_config();
        
        // Test with empty spool - should not error
        let result = show_statistics(ctx, None, false);
        assert!(result.is_ok());
        
        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }
}