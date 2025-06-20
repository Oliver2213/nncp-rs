//! NNCP packet implementation
//!
//! This module provides the core packet structure and operations for NNCP.

use std::io::{self, Read, Write};
use bytes::{BufMut, BytesMut};
use serde::{Serialize, Deserialize};

use crate::magic::NNCP_P_V3;
use crate::packet::Error;
use crate::constants::MAX_PATH_SIZE;

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
}
