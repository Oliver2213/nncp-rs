//! File packet implementation for NNCP
//!
//! This module provides the file packet type, which is used for transferring files.

use crate::{
    Error,
    Packet,
    PacketType,
    packet::PacketContent,
};

/// File packet for NNCP
#[derive(Debug, Clone)]
pub struct FilePacket {
    /// Path to the file
    pub path: String,
}

impl FilePacket {
    /// Create a new file packet with the given path
    pub fn new(path: &str) -> Result<Self, Error> {
        Ok(Self {
            path: path.to_string(),
        })
    }
    
    /// Encode the file packet with the given niceness level
    pub fn encode<W: std::io::Write>(&self, writer: &mut W, nice: u8) -> Result<usize, Error> {
        let packet = self.to_packet(nice)?;
        Ok(packet.encode(writer)?)
    }
    
    /// Decode a file packet from a reader
    pub fn decode<R: std::io::Read>(reader: &mut R) -> Result<(Self, u8), Error> {
        let packet = Packet::decode(reader)?;
        if packet.packet_type != PacketType::File {
            return Err(Error::InvalidPacketType {
                expected: PacketType::File,
                actual: packet.packet_type,
            });
        }
        
        Ok((Self::from_packet(&packet)?, packet.nice))
    }
}

impl PacketContent for FilePacket {
    fn from_packet(packet: &Packet) -> Result<Self, Error> {
        if packet.packet_type != PacketType::File {
            return Err(Error::InvalidPacketType {
                expected: PacketType::File,
                actual: packet.packet_type,
            });
        }
        
        let path = std::str::from_utf8(packet.path())
            .map_err(|_| Error::InvalidUtf8)?
            .to_string();
            
        Ok(Self { path })
    }
    
    fn to_packet(&self, nice: u8) -> Result<Packet, Error> {
        Packet::new(
            PacketType::File,
            nice,
            self.path.as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    
    #[test]
    fn test_file_packet_roundtrip() {
        let path = "/path/to/file.txt";
        let file_packet = FilePacket::new(path).unwrap();
        
        let mut buffer = Vec::new();
        file_packet.encode(&mut buffer, 10).unwrap();
        
        let mut cursor = Cursor::new(buffer);
        let (decoded, nice) = FilePacket::decode(&mut cursor).unwrap();
        
        assert_eq!(decoded.path, path);
        assert_eq!(nice, 10);
    }
}
