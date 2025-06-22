//! nncp-ack command implementation

use nncp_rs::constants::{
    NNCP_E_V6_MAGIC, NICE_FLASH_BASE, NICE_PRIORITY_BASE, 
    NICE_NORMAL_BASE, NICE_BULK_BASE, NICE_MAX
};
use nncp_rs::packet::{PacketType, AckPacket};
use nncp_rs::magic::NNCP_P_V3;
use nncp_rs::nncp::NodeID;
use crate::cli::Context;
use std::io::Read;
use std::fs;
use std::path::Path;
use anyhow::Error;

/// Send packet receipt acknowledgements (equivalent to nncp-ack)
pub fn send_acknowledgements(
    ctx: Context,
    all: bool,
    nodes_raw: Option<&str>,
    pkt_raw: Option<&str>,
    nice_raw: &str,
    minsize_raw: Option<i64>,
    _via_override: Option<&str>, // TODO: Implement via override
    quiet: bool,
) -> Result<(), Error> {
    // Parse niceness level
    let nice = parse_niceness(nice_raw)?;
    
    // Determine which nodes to process
    let mut target_nodes = Vec::new();
    
    if all {
        if nodes_raw.is_some() {
            return Err(anyhow::anyhow!("Cannot use both --all and --node options"));
        }
        // Add all neighbor nodes
        for node_id in ctx.neighbors.keys() {
            target_nodes.push(*node_id);
        }
    } else if let Some(nodes_str) = nodes_raw {
        // Parse comma-separated node list
        for node_name in nodes_str.split(',') {
            let node_name = node_name.trim();
            match ctx.neighbor_aliases.get(node_name) {
                Some(node_id) => target_nodes.push(*node_id),
                None => {
                    // Try to decode as base32 NodeID
                    match base32::decode(base32::Alphabet::RFC4648 { padding: false }, node_name) {
                        Some(bytes) if bytes.len() == 32 => {
                            let mut node_id = [0u8; 32];
                            node_id.copy_from_slice(&bytes);
                            target_nodes.push(node_id);
                        }
                        _ => return Err(anyhow::anyhow!("Unknown node: {}", node_name)),
                    }
                }
            }
        }
    } else {
        return Err(anyhow::anyhow!("Must specify either --all or --node option"));
    }
    
    if target_nodes.is_empty() {
        return Err(anyhow::anyhow!("No nodes to process"));
    }
    
    // Handle specific packet ACK
    if let Some(pkt_name) = pkt_raw {
        if target_nodes.len() != 1 {
            return Err(anyhow::anyhow!("--pkt option requires exactly one node"));
        }
        
        let node_id = target_nodes[0];
        let minsize = calculate_minsize(minsize_raw, &ctx, &node_id)?;
        
        let ack_pkt_name = send_single_ack(&ctx, &node_id, pkt_name, nice, minsize, quiet)?;
        
        // Output to stdout (Go version uses FD 4, but we'll use stdout for simplicity)
        println!("{}/{}", 
                 base32::encode(base32::Alphabet::RFC4648 { padding: false }, &node_id),
                 ack_pkt_name);
        return Ok(());
    }
    
    // Process all packets for the specified nodes
    let mut has_errors = false;
    
    for node_id in target_nodes {
        let minsize = calculate_minsize(minsize_raw, &ctx, &node_id)?;
        
        match process_node_packets(&ctx, &node_id, nice, minsize, quiet) {
            Ok(ack_packets) => {
                // Output created ACK packet names
                for ack_pkt_name in ack_packets {
                    println!("{}/{}", 
                             base32::encode(base32::Alphabet::RFC4648 { padding: false }, &node_id),
                             ack_pkt_name);
                }
            }
            Err(e) => {
                if !quiet {
                    eprintln!("Error processing node {}: {}", 
                             base32::encode(base32::Alphabet::RFC4648 { padding: false }, &node_id), 
                             e);
                }
                has_errors = true;
            }
        }
    }
    
    if has_errors {
        return Err(anyhow::anyhow!("Some packets could not be processed"));
    }
    
    Ok(())
}

/// Parse niceness string to u8 value
fn parse_niceness(nice_str: &str) -> Result<u8, Error> {
    match nice_str {
        "F" => Ok(NICE_FLASH_BASE),
        "P" => Ok(NICE_PRIORITY_BASE), 
        "N" => Ok(NICE_NORMAL_BASE),
        "B" => Ok(NICE_BULK_BASE),
        "MAX" => Ok(NICE_MAX),
        _ => {
            // Try to parse offset format like F+10, P-5, etc.
            if nice_str.len() >= 2 {
                let base_char = nice_str.chars().next().unwrap();
                let offset_str = &nice_str[1..];
                
                let base = match base_char {
                    'F' => NICE_FLASH_BASE,
                    'P' => NICE_PRIORITY_BASE,
                    'N' => NICE_NORMAL_BASE,
                    'B' => NICE_BULK_BASE,
                    _ => return Err(anyhow::anyhow!("Invalid niceness format: {}", nice_str)),
                };
                
                if offset_str.is_empty() {
                    return Ok(base);
                }
                
                let offset: i16 = offset_str.parse()
                    .map_err(|_| anyhow::anyhow!("Invalid niceness offset: {}", offset_str))?;
                
                let result = base as i16 + offset;
                if result < 0 || result > 255 {
                    return Err(anyhow::anyhow!("Niceness value out of range: {}", result));
                }
                
                Ok(result as u8)
            } else {
                Err(anyhow::anyhow!("Invalid niceness format: {}", nice_str))
            }
        }
    }
}

/// Calculate minimum size for ACK packets
fn calculate_minsize(minsize_raw: Option<i64>, _ctx: &Context, _node_id: &NodeID) -> Result<i64, Error> {
    match minsize_raw {
        Some(size) if size > 0 => Ok(size * 1024), // Convert KiB to bytes
        Some(0) => Ok(0),
        Some(_) => {
            // Use node-specific ACK minimum size (TODO: implement in node config)
            // For now, default to 0
            Ok(0)
        }
        None => {
            // Use node-specific ACK minimum size (TODO: implement in node config)
            // For now, default to 0
            Ok(0)
        }
    }
}

/// Send ACK for a single specific packet
fn send_single_ack(
    _ctx: &Context,
    node_id: &NodeID,
    pkt_name: &str,
    _nice: u8,
    _minsize: i64,
    quiet: bool,
) -> Result<String, Error> {
    // TODO: Implement actual ACK packet transmission
    // For now, just create an ACK packet and return a placeholder name
    
    let _ack_packet = AckPacket::new(pkt_name)?;
    
    if !quiet {
        println!("ACKing packet {} for node {}", 
                pkt_name,
                base32::encode(base32::Alphabet::RFC4648 { padding: false }, node_id));
    }
    
    // TODO: Actually send the ACK packet through the NNCP system
    // This would involve creating a packet file in the tx directory
    
    // Return a placeholder ACK packet name
    Ok(format!("ack-{}", pkt_name))
}

/// Process all received packets for a node and create ACKs
fn process_node_packets(
    ctx: &Context,
    node_id: &NodeID,
    nice: u8,
    minsize: i64,
    quiet: bool,
) -> Result<Vec<String>, Error> {
    let node_dir = ctx.spool_path.join(
        base32::encode(base32::Alphabet::RFC4648 { padding: false }, node_id)
    );
    let rx_dir = node_dir.join("rx");
    
    if !rx_dir.exists() {
        return Ok(Vec::new()); // No received packets
    }
    
    let mut ack_packets = Vec::new();
    
    for entry in fs::read_dir(&rx_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if !path.is_file() {
            continue;
        }
        
        let file_name = match path.file_name().and_then(|s| s.to_str()) {
            Some(name) => name,
            None => continue,
        };
        
        // Skip partial and no-check files
        if file_name.ends_with(".part") || file_name.ends_with(".nock") {
            continue;
        }
        
        match process_received_packet(&path, node_id, nice, minsize, quiet) {
            Ok(Some(ack_name)) => {
                ack_packets.push(ack_name);
            }
            Ok(None) => {
                // Packet was skipped (e.g., it's already an ACK)
            }
            Err(e) => {
                if !quiet {
                    eprintln!("Warning: Failed to process packet {}: {}", file_name, e);
                }
                // Continue processing other packets
            }
        }
    }
    
    Ok(ack_packets)
}

/// Process a single received packet and create ACK if needed
fn process_received_packet(
    packet_path: &Path,
    node_id: &NodeID,
    _nice: u8,
    _minsize: i64,
    quiet: bool,
) -> Result<Option<String>, Error> {
    let mut file = fs::File::open(packet_path)?;
    
    // Read packet header to determine if it's encrypted or plain
    let mut magic_buf = [0u8; 8];
    file.read_exact(&mut magic_buf)?;
    
    // Check if it's an encrypted packet
    if magic_buf == NNCP_E_V6_MAGIC {
        // For encrypted packets, we need to decrypt to check the packet type
        // For now, assume it's not an ACK packet and create an ACK
        // TODO: Implement proper decryption and packet type checking
        
        let pkt_name = packet_path.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid packet filename"))?;
        
        if !quiet {
            println!("ACKing encrypted packet {} for node {}", 
                    pkt_name,
                    base32::encode(base32::Alphabet::RFC4648 { padding: false }, node_id));
        }
        
        // TODO: Actually create and send the ACK packet
        return Ok(Some(format!("ack-{}", pkt_name)));
    }
    
    // Check if it's a plain packet
    if magic_buf == NNCP_P_V3.bytes {
        // Read packet type to check if it's already an ACK
        let mut packet_type_buf = [0u8; 1];
        file.read_exact(&mut packet_type_buf)?;
        
        if packet_type_buf[0] == PacketType::ACK as u8 {
            if !quiet {
                println!("Skipping ACK packet (already an ACK): {}", 
                        packet_path.file_name().unwrap().to_str().unwrap());
            }
            return Ok(None); // Skip ACK packets
        }
        
        let pkt_name = packet_path.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid packet filename"))?;
        
        if !quiet {
            println!("ACKing plain packet {} for node {}", 
                    pkt_name,
                    base32::encode(base32::Alphabet::RFC4648 { padding: false }, node_id));
        }
        
        // TODO: Actually create and send the ACK packet
        return Ok(Some(format!("ack-{}", pkt_name)));
    }
    
    Err(anyhow::anyhow!("Unknown packet format"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_niceness() {
        // Test base niceness levels
        assert_eq!(parse_niceness("F").unwrap(), NICE_FLASH_BASE);
        assert_eq!(parse_niceness("P").unwrap(), NICE_PRIORITY_BASE);
        assert_eq!(parse_niceness("N").unwrap(), NICE_NORMAL_BASE);
        assert_eq!(parse_niceness("B").unwrap(), NICE_BULK_BASE);
        assert_eq!(parse_niceness("MAX").unwrap(), NICE_MAX);
        
        // Test offset formats
        assert_eq!(parse_niceness("F+10").unwrap(), NICE_FLASH_BASE + 10);
        assert_eq!(parse_niceness("P-5").unwrap(), NICE_PRIORITY_BASE - 5);
        assert_eq!(parse_niceness("N+0").unwrap(), NICE_NORMAL_BASE);
        
        // Test invalid formats
        assert!(parse_niceness("X").is_err());
        assert!(parse_niceness("F+1000").is_err()); // Out of range
        assert!(parse_niceness("").is_err());
    }

    #[test]
    fn test_calculate_minsize() {
        let ctx = Context::new("/tmp/config", "/tmp/log", "/tmp/spool");
        let node_id = [0u8; 32];
        
        // Test positive size
        assert_eq!(calculate_minsize(Some(10), &ctx, &node_id).unwrap(), 10240);
        
        // Test zero size
        assert_eq!(calculate_minsize(Some(0), &ctx, &node_id).unwrap(), 0);
        
        // Test default (None)
        assert_eq!(calculate_minsize(None, &ctx, &node_id).unwrap(), 0);
    }
}