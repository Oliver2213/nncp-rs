//! Trns packet implementation for NNCP
//!
//! This module provides the transit packet type, which is used for forwarding packets
//! through intermediate nodes to their final destination.

use crate::packet::{
    Error,
    Packet,
    PacketType,
    PacketContent,
};
use crate::nncp::NodeID;
use std::io::{Read, Write};

/// Transit packet for NNCP
/// 
/// Transit packets are used to forward encrypted packets through intermediate nodes.
/// The path field contains the final destination NodeID (32 bytes), and the payload
/// contains the entire encrypted packet that needs to be forwarded.
#[derive(Debug, Clone)]
pub struct TrnsPacket {
    /// Destination node ID (32 bytes)
    pub destination: NodeID,
    /// Encrypted packet payload to be forwarded
    pub encrypted_payload: Vec<u8>,
}

impl TrnsPacket {
    /// Create a new transit packet with destination node ID and encrypted payload
    pub fn new(destination: NodeID, encrypted_payload: Vec<u8>) -> Result<Self, Error> {
        Ok(Self {
            destination,
            encrypted_payload,
        })
    }
    
    /// Encode the transit packet header and write payload separately
    /// 
    /// This encodes only the packet header (with destination in path field).
    /// The encrypted payload should be written separately after this.
    pub fn encode_header<W: Write>(&self, writer: &mut W, nice: u8) -> Result<usize, Error> {
        let packet = self.to_packet(nice)?;
        Ok(packet.encode(writer)?)
    }
    
    /// Write the encrypted payload to the writer
    pub fn encode_payload<W: Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        writer.write_all(&self.encrypted_payload)?;
        Ok(self.encrypted_payload.len())
    }
    
    /// Encode the complete transit packet (header + payload)
    pub fn encode<W: Write>(&self, writer: &mut W, nice: u8) -> Result<usize, Error> {
        let header_size = self.encode_header(writer, nice)?;
        let payload_size = self.encode_payload(writer)?;
        Ok(header_size + payload_size)
    }
    
    /// Decode a transit packet header and read payload separately
    pub fn decode_with_payload<R: Read>(reader: &mut R, payload_size: usize) -> Result<(Self, u8), Error> {
        let packet = Packet::decode(reader)?;
        if packet.packet_type != PacketType::Trns {
            return Err(Error::InvalidPacketType {
                expected: PacketType::Trns,
                actual: packet.packet_type,
            });
        }
        
        // Read encrypted payload
        let mut encrypted_payload = vec![0u8; payload_size];
        reader.read_exact(&mut encrypted_payload)?;
        
        let trns_packet = Self::from_packet_with_payload(&packet, encrypted_payload)?;
        Ok((trns_packet, packet.nice))
    }
    
    /// Decode only the transit packet header (for compatibility)
    pub fn decode<R: Read>(reader: &mut R) -> Result<(Self, u8), Error> {
        let packet = Packet::decode(reader)?;
        if packet.packet_type != PacketType::Trns {
            return Err(Error::InvalidPacketType {
                expected: PacketType::Trns,
                actual: packet.packet_type,
            });
        }
        
        Ok((Self::from_packet(&packet)?, packet.nice))
    }
    
    /// Get the destination node ID
    pub fn destination(&self) -> &NodeID {
        &self.destination
    }
    
    /// Get the encrypted payload
    pub fn payload(&self) -> &[u8] {
        &self.encrypted_payload
    }
}

impl TrnsPacket {
    /// Create TrnsPacket from packet header with separate payload
    fn from_packet_with_payload(packet: &Packet, encrypted_payload: Vec<u8>) -> Result<Self, Error> {
        if packet.packet_type != PacketType::Trns {
            return Err(Error::InvalidPacketType {
                expected: PacketType::Trns,
                actual: packet.packet_type,
            });
        }
        
        // Path field should contain exactly 32 bytes (NodeID)
        let path_data = packet.path();
        if path_data.len() != 32 {
            return Err(Error::InvalidPacketFormat(
                format!("Transit packet path must be 32 bytes (NodeID), got {}", path_data.len())
            ));
        }
        
        let mut destination = [0u8; 32];
        destination.copy_from_slice(path_data);
        
        Ok(Self {
            destination,
            encrypted_payload,
        })
    }
}

impl PacketContent for TrnsPacket {
    fn from_packet(packet: &Packet) -> Result<Self, Error> {
        if packet.packet_type != PacketType::Trns {
            return Err(Error::InvalidPacketType {
                expected: PacketType::Trns,
                actual: packet.packet_type,
            });
        }
        
        // Path field should contain exactly 32 bytes (NodeID)
        let path_data = packet.path();
        if path_data.len() != 32 {
            return Err(Error::InvalidPacketFormat(
                format!("Transit packet path must be 32 bytes (NodeID), got {}", path_data.len())
            ));
        }
        
        let mut destination = [0u8; 32];
        destination.copy_from_slice(path_data);
        
        Ok(Self {
            destination,
            encrypted_payload: Vec::new(), // No payload in header-only decode
        })
    }
    
    fn to_packet(&self, nice: u8) -> Result<Packet, Error> {
        // Use the destination NodeID as the path field
        Packet::new(
            PacketType::Trns,
            nice,
            &self.destination,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    
    #[test]
    fn test_trns_packet_roundtrip() {
        // Create a sample destination NodeID and encrypted payload
        let destination = [0x42u8; 32]; // Sample 32-byte NodeID
        let encrypted_payload = b"encrypted packet data for forwarding".to_vec();
        
        let trns_packet = TrnsPacket::new(destination, encrypted_payload.clone()).unwrap();
        
        let mut buffer = Vec::new();
        trns_packet.encode(&mut buffer, 10).unwrap();
        
        let mut cursor = Cursor::new(buffer);
        let (decoded, nice) = TrnsPacket::decode_with_payload(&mut cursor, encrypted_payload.len()).unwrap();
        
        assert_eq!(decoded.destination, destination);
        assert_eq!(decoded.encrypted_payload, encrypted_payload);
        assert_eq!(nice, 10);
    }
    
    #[test]
    fn test_trns_packet_header_only() {
        let destination = [0x33u8; 32];
        let encrypted_payload = b"test payload".to_vec();
        
        let trns_packet = TrnsPacket::new(destination, encrypted_payload).unwrap();
        
        let mut buffer = Vec::new();
        trns_packet.encode_header(&mut buffer, 15).unwrap();
        
        let mut cursor = Cursor::new(buffer);
        let (decoded, nice) = TrnsPacket::decode(&mut cursor).unwrap();
        
        assert_eq!(decoded.destination, destination);
        assert_eq!(decoded.encrypted_payload, Vec::<u8>::new()); // Empty in header-only decode
        assert_eq!(nice, 15);
    }
    
    #[test]
    fn test_trns_packet_invalid_node_id_size() {
        // Test that transit packets reject non-32-byte path data
        let packet = Packet::new(PacketType::Trns, 10, b"short_path").unwrap();
        let result = TrnsPacket::from_packet(&packet);
        
        assert!(result.is_err());
        if let Err(Error::InvalidPacketFormat(msg)) = result {
            assert!(msg.contains("must be 32 bytes"));
        } else {
            panic!("Expected InvalidPacketFormat error");
        }
    }
    
    #[test]
    fn test_trns_packet_getters() {
        let destination = [0x11u8; 32];
        let payload = b"test payload data".to_vec();
        
        let trns_packet = TrnsPacket::new(destination, payload.clone()).unwrap();
        
        assert_eq!(trns_packet.destination(), &destination);
        assert_eq!(trns_packet.payload(), payload.as_slice());
    }
}
