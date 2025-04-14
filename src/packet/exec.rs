//! Exec packet implementation for NNCP
//!
//! This module provides the exec packet types, which are used for executing commands.

use crate::packet::{
    Error,
    Packet,
    PacketType,
    PacketContent,
};

/// Exec packet for NNCP
#[derive(Debug, Clone)]
pub struct ExecPacket {
    /// Command to execute
    pub command: String,
}

impl ExecPacket {
    /// Create a new exec packet with the given command
    pub fn new(command: &str) -> Result<Self, Error> {
        Ok(Self {
            command: command.to_string(),
        })
    }
    
    /// Encode the exec packet with the given niceness level
    pub fn encode<W: std::io::Write>(&self, writer: &mut W, nice: u8) -> Result<usize, Error> {
        let packet = self.to_packet(nice)?;
        Ok(packet.encode(writer)?)
    }
    
    /// Decode an exec packet from a reader
    pub fn decode<R: std::io::Read>(reader: &mut R) -> Result<(Self, u8), Error> {
        let packet = Packet::decode(reader)?;
        if packet.packet_type != PacketType::Exec {
            return Err(Error::InvalidPacketType {
                expected: PacketType::Exec,
                actual: packet.packet_type,
            });
        }
        
        Ok((Self::from_packet(&packet)?, packet.nice))
    }
}

impl PacketContent for ExecPacket {
    fn from_packet(packet: &Packet) -> Result<Self, Error> {
        if packet.packet_type != PacketType::Exec {
            return Err(Error::InvalidPacketType {
                expected: PacketType::Exec,
                actual: packet.packet_type,
            });
        }
        
        let command = std::str::from_utf8(packet.path())
            .map_err(|_| Error::InvalidUtf8)?
            .to_string();
            
        Ok(Self { command })
    }
    
    fn to_packet(&self, nice: u8) -> Result<Packet, Error> {
        Packet::new(
            PacketType::Exec,
            nice,
            self.command.as_bytes(),
        )
    }
}

/// ExecFat packet for NNCP
/// 
/// This is used for executing commands with larger arguments
#[derive(Debug, Clone)]
pub struct ExecFatPacket {
    /// Command to execute
    pub command: String,
}

impl ExecFatPacket {
    /// Create a new exec fat packet with the given command
    pub fn new(command: &str) -> Result<Self, Error> {
        Ok(Self {
            command: command.to_string(),
        })
    }
    
    /// Encode the exec fat packet with the given niceness level
    pub fn encode<W: std::io::Write>(&self, writer: &mut W, nice: u8) -> Result<usize, Error> {
        let packet = self.to_packet(nice)?;
        Ok(packet.encode(writer)?)
    }
    
    /// Decode an exec fat packet from a reader
    pub fn decode<R: std::io::Read>(reader: &mut R) -> Result<(Self, u8), Error> {
        let packet = Packet::decode(reader)?;
        if packet.packet_type != PacketType::ExecFat {
            return Err(Error::InvalidPacketType {
                expected: PacketType::ExecFat,
                actual: packet.packet_type,
            });
        }
        
        Ok((Self::from_packet(&packet)?, packet.nice))
    }
}

impl PacketContent for ExecFatPacket {
    fn from_packet(packet: &Packet) -> Result<Self, Error> {
        if packet.packet_type != PacketType::ExecFat {
            return Err(Error::InvalidPacketType {
                expected: PacketType::ExecFat,
                actual: packet.packet_type,
            });
        }
        
        let command = std::str::from_utf8(packet.path())
            .map_err(|_| Error::InvalidUtf8)?
            .to_string();
            
        Ok(Self { command })
    }
    
    fn to_packet(&self, nice: u8) -> Result<Packet, Error> {
        Packet::new(
            PacketType::ExecFat,
            nice,
            self.command.as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    
    #[test]
    fn test_exec_packet_roundtrip() {
        let command = "echo 'Hello, world!'";
        let exec_packet = ExecPacket::new(command).unwrap();
        
        let mut buffer = Vec::new();
        exec_packet.encode(&mut buffer, 10).unwrap();
        
        let mut cursor = Cursor::new(buffer);
        let (decoded, nice) = ExecPacket::decode(&mut cursor).unwrap();
        
        assert_eq!(decoded.command, command);
        assert_eq!(nice, 10);
    }
    
    #[test]
    fn test_exec_fat_packet_roundtrip() {
        let command = "echo 'This is a much longer command with many arguments'";
        let exec_fat_packet = ExecFatPacket::new(command).unwrap();
        
        let mut buffer = Vec::new();
        exec_fat_packet.encode(&mut buffer, 10).unwrap();
        
        let mut cursor = Cursor::new(buffer);
        let (decoded, nice) = ExecFatPacket::decode(&mut cursor).unwrap();
        
        assert_eq!(decoded.command, command);
        assert_eq!(nice, 10);
    }
}
