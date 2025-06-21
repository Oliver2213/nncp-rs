//! NNCP packet implementation
//!
//! This module provides the core packet structure and operations for NNCP.

use std::io::{self, Read, Write};
use bytes::{BufMut, BytesMut};
use serde::{Serialize, Deserialize};

use crate::magic::NNCP_P_V3;
use crate::packet::Error;
use crate::constants::{
    MAX_PATH_SIZE, NICE_FLASH_MIN, NICE_FLASH_MAX, NICE_FLASH_BASE,
    NICE_PRIORITY_MIN, NICE_PRIORITY_MAX, NICE_PRIORITY_BASE,
    NICE_NORMAL_MIN, NICE_NORMAL_MAX, NICE_NORMAL_BASE,
    NICE_BULK_MIN, NICE_BULK_MAX, NICE_BULK_BASE, NICE_MAX
};

/// Type of NNCP packet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    /// File transfer packet
    File = 0,
    /// File request packet
    Freq = 1,
    /// Command execution packet
    Exec = 2,
    /// Transit packet
    Trns = 3,
    /// Fat command execution packet
    ExecFat = 4,
    /// Area packet
    Area = 5,
    /// Acknowledgment packet
    ACK = 6,
}

impl TryFrom<u8> for PacketType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PacketType::File),
            1 => Ok(PacketType::Freq),
            2 => Ok(PacketType::Exec),
            3 => Ok(PacketType::Trns),
            4 => Ok(PacketType::ExecFat),
            5 => Ok(PacketType::Area),
            6 => Ok(PacketType::ACK),
            _ => Err(Error::BadPacketType),
        }
    }
}

/// NNCP packet structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    /// Magic number identifying the packet type and version
    pub magic: [u8; 8],
    /// Type of packet
    pub packet_type: PacketType,
    /// Niceness level (priority, lower is more important)
    pub nice: u8,
    /// Path length
    pub path_len: u8,
    /// Path data (up to MAX_PATH_SIZE bytes)
    #[serde(with = "serde_bytes")]
    pub path: [u8; MAX_PATH_SIZE],
}

/// Trait for packet types that can be converted to/from the base Packet
pub trait PacketContent: Sized {
    /// Convert from a base Packet to this specific packet type
    fn from_packet(packet: &Packet) -> Result<Self, Error>;
    
    /// Convert this specific packet type to a base Packet
    fn to_packet(&self, nice: u8) -> Result<Packet, Error>;
}

impl Packet {
    /// Create a new packet with the given type, niceness, and path
    pub fn new(packet_type: PacketType, nice: u8, path: &[u8]) -> Result<Self, Error> {
        if path.len() > MAX_PATH_SIZE {
            return Err(Error::PathTooLong(MAX_PATH_SIZE));
        }

        let mut packet = Self {
            magic: NNCP_P_V3.bytes,
            packet_type,
            nice,
            path_len: path.len() as u8,
            path: [0; MAX_PATH_SIZE],
        };

        // Copy path data
        packet.path[..path.len()].copy_from_slice(path);

        Ok(packet)
    }

    /// Calculate the overhead size of this packet when serialized
    /// Equivalent to Go's PktOverhead calculation
    pub fn overhead(&self) -> Result<i64, Error> {
        // Serialize the packet to calculate actual overhead
        let mut buffer = Vec::new();
        serde_xdr::to_writer(&mut buffer, self)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        Ok(buffer.len() as i64)
    }

    /// Calculate the overhead size for encrypted packets
    /// Equivalent to Go's PktEncOverhead calculation
    pub fn enc_overhead(nice: u8, sender: &[u8; 32], recipient: &[u8; 32]) -> Result<i64, Error> {
        use crate::packet::encrypted::PktEnc;
        
        // Create a sample encrypted packet header to calculate overhead
        let pkt_enc = PktEnc {
            magic: crate::constants::NNCP_E_V6_MAGIC,
            nice,
            sender: *sender,
            recipient: *recipient,
            exch_pub: [0u8; 32], // Sample public key
            sign: [0u8; 64], // Sample signature
        };
        
        let mut buffer = Vec::new();
        serde_xdr::to_writer(&mut buffer, &pkt_enc)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        Ok(buffer.len() as i64)
    }

    /// Calculate the size overhead for packet size information
    /// Equivalent to Go's size calculation for PktSize structure
    pub fn size_overhead() -> Result<i64, Error> {
        use crate::packet::encrypted::PktSize;
        
        // Create a sample PktSize to calculate overhead
        let pkt_size = PktSize {
            payload: 0,
            pad: 0,
        };
        
        let mut buffer = Vec::new();
        serde_xdr::to_writer(&mut buffer, &pkt_size)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        Ok(buffer.len() as i64)
    }

    /// Encode the packet to a writer
    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut buffer = BytesMut::with_capacity(
            8 + // magic
            1 + // packet type
            1 + // nice
            1 + // path length
            self.path_len as usize // path data
        );

        // Write magic
        buffer.put_slice(&self.magic);
        
        // Write packet type
        buffer.put_u8(self.packet_type as u8);
        
        // Write nice
        buffer.put_u8(self.nice);
        
        // Write path length
        buffer.put_u8(self.path_len);
        
        // Write path data
        buffer.put_slice(&self.path[..self.path_len as usize]);

        // Write to output
        writer.write_all(&buffer)?;
        
        Ok(buffer.len())
    }

    /// Decode a packet from a reader
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;

        // Check if we recognize this magic number
        if magic != NNCP_P_V3.bytes {
            return Err(Error::BadMagic);
        }

        let mut packet_type_byte = [0u8; 1];
        reader.read_exact(&mut packet_type_byte)?;
        let packet_type = PacketType::try_from(packet_type_byte[0])?;

        let mut nice = [0u8; 1];
        reader.read_exact(&mut nice)?;

        let mut path_len = [0u8; 1];
        reader.read_exact(&mut path_len)?;

        let mut path = [0u8; MAX_PATH_SIZE];
        reader.read_exact(&mut path[..path_len[0] as usize])?;

        Ok(Self {
            magic,
            packet_type,
            nice: nice[0],
            path_len: path_len[0],
            path,
        })
    }

    /// Get the path as a byte slice
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }

    /// Get the path as a string if it's valid UTF-8
    pub fn path_str(&self) -> Option<&str> {
        std::str::from_utf8(self.path()).ok()
    }
    
    /// Convert this packet to a specific packet type
    pub fn to_specific<T: PacketContent>(&self) -> Result<T, Error> {
        T::from_packet(self)
    }

    /// Format niceness value (equivalent to Go's NicenessFmt)
    pub fn format_niceness(&self) -> String {
        Self::format_niceness_value(self.nice)
    }

    /// Format niceness value for any u8 niceness level
    pub fn format_niceness_value(nice: u8) -> String {
        match nice {
            NICE_FLASH_MIN..=NICE_FLASH_MAX => {
                let offset = nice as i16 - NICE_FLASH_BASE as i16;
                if offset == 0 {
                    "F".to_string()
                } else {
                    format!("F{:+}", offset)
                }
            }
            NICE_PRIORITY_MIN..=NICE_PRIORITY_MAX => {
                let offset = nice as i16 - NICE_PRIORITY_BASE as i16;
                if offset == 0 {
                    "P".to_string()
                } else {
                    format!("P{:+}", offset)
                }
            }
            NICE_NORMAL_MIN..=NICE_NORMAL_MAX => {
                let offset = nice as i16 - NICE_NORMAL_BASE as i16;
                if offset == 0 {
                    "N".to_string()
                } else {
                    format!("N{:+}", offset)
                }
            }
            NICE_BULK_MIN..=NICE_BULK_MAX => {
                let offset = nice as i16 - NICE_BULK_BASE as i16;
                if offset == 0 {
                    "B".to_string()
                } else {
                    format!("B{:+}", offset)
                }
            }
            NICE_MAX => "MAX".to_string(),
        }
    }

    /// Format path based on packet type (equivalent to Go's path formatting)
    pub fn format_path(&self) -> String {
        Self::format_path_for_type(self.packet_type, self.path())
    }

    /// Format path for a specific packet type and path data
    pub fn format_path_for_type(packet_type: PacketType, path: &[u8]) -> String {
        match packet_type {
            PacketType::Exec => {
                // Replace null bytes with spaces for exec commands
                String::from_utf8_lossy(path).replace('\0', " ")
            }
            PacketType::Trns => {
                // For transit packets, path should be a NodeID (32 bytes)
                if path.len() >= 32 {
                    let node_id: [u8; 32] = path[..32].try_into().unwrap_or([0; 32]);
                    // TODO: Look up node name from configuration
                    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &node_id)
                } else {
                    hex::encode(path)
                }
            }
            PacketType::Area => {
                // For area packets, path should be an area ID (32 bytes)
                if path.len() >= 32 {
                    let area_id: [u8; 32] = path[..32].try_into().unwrap_or([0; 32]);
                    // TODO: Look up area name from configuration
                    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &area_id)
                } else {
                    hex::encode(path)
                }
            }
            PacketType::ACK => {
                // For ACK packets, path should be a packet ID (32 bytes)
                if path.len() >= 32 {
                    let pkt_id: [u8; 32] = path[..32].try_into().unwrap_or([0; 32]);
                    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &pkt_id)
                } else {
                    hex::encode(path)
                }
            }
            _ => {
                // For other packet types, treat as UTF-8 string
                String::from_utf8_lossy(path).to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_packet_roundtrip() {
        let path = b"/path/to/file.txt";
        let packet = Packet::new(PacketType::File, 10, path).unwrap();
        
        let mut buffer = Vec::new();
        packet.encode(&mut buffer).unwrap();
        
        let mut cursor = Cursor::new(buffer);
        let decoded = Packet::decode(&mut cursor).unwrap();
        
        assert_eq!(decoded.packet_type, PacketType::File);
        assert_eq!(decoded.nice, 10);
        assert_eq!(decoded.path(), path);
    }

    #[test]
    fn test_path_too_long() {
        let long_path = vec![b'a'; MAX_PATH_SIZE + 1];
        let result = Packet::new(PacketType::File, 10, &long_path);
        assert!(result.is_err());
        
        if let Err(Error::PathTooLong(max)) = result {
            assert_eq!(max, MAX_PATH_SIZE);
        } else {
            panic!("Expected PathTooLong error");
        }
    }

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
    fn test_packet_methods() {
        let path = b"/test/file.txt";
        let packet = Packet::new(PacketType::File, 160, path).unwrap();
        
        // Test format_niceness method
        assert_eq!(packet.format_niceness(), "N");
        
        // Test format_path method
        assert_eq!(packet.format_path(), "/test/file.txt");
    }
}
