//! Example showing how to read and decode different NNCP packet types

use std::fs::File;
use std::io::BufReader;
use nncp_packet::{Packet, PacketType, FilePacket, ExecPacket, FreqPacket, TrnsPacket, AckPacket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read a file packet
    let file = File::open("file_packet.bin")?;
    let mut reader = BufReader::new(file);
    let (file_packet, nice) = FilePacket::decode(&mut reader)?;
    println!("Read file packet:");
    println!("  Path: {}", file_packet.path);
    println!("  Nice: {}", nice);
    
    // Read an exec packet
    let file = File::open("exec_packet.bin")?;
    let mut reader = BufReader::new(file);
    let (exec_packet, nice) = ExecPacket::decode(&mut reader)?;
    println!("Read exec packet:");
    println!("  Command: {}", exec_packet.command);
    println!("  Nice: {}", nice);
    
    // Read a freq packet
    let file = File::open("freq_packet.bin")?;
    let mut reader = BufReader::new(file);
    let (freq_packet, nice) = FreqPacket::decode(&mut reader)?;
    println!("Read freq packet:");
    println!("  Path: {}", freq_packet.path);
    println!("  Nice: {}", nice);
    
    // Read a transit packet
    let file = File::open("trns_packet.bin")?;
    let mut reader = BufReader::new(file);
    let (trns_packet, nice) = TrnsPacket::decode(&mut reader)?;
    println!("Read transit packet:");
    println!("  Path: {}", trns_packet.path);
    println!("  Nice: {}", nice);
    
    // Read an acknowledgment packet
    let file = File::open("ack_packet.bin")?;
    let mut reader = BufReader::new(file);
    let (ack_packet, nice) = AckPacket::decode(&mut reader)?;
    println!("Read acknowledgment packet:");
    println!("  Path: {}", ack_packet.path);
    println!("  Nice: {}", nice);
    
    // Generic packet reading example
    let file = File::open("file_packet.bin")?;
    let mut reader = BufReader::new(file);
    let packet = Packet::decode(&mut reader)?;
    
    // Convert to specific packet type based on the packet type
    match packet.packet_type {
        PacketType::File => {
            let file_packet = packet.to_specific::<FilePacket>()?;
            println!("Generic read file packet: {}", file_packet.path);
        },
        PacketType::Exec => {
            let exec_packet = packet.to_specific::<ExecPacket>()?;
            println!("Generic read exec packet: {}", exec_packet.command);
        },
        PacketType::Freq => {
            let freq_packet = packet.to_specific::<FreqPacket>()?;
            println!("Generic read freq packet: {}", freq_packet.path);
        },
        PacketType::Trns => {
            let trns_packet = packet.to_specific::<TrnsPacket>()?;
            println!("Generic read transit packet: {}", trns_packet.path);
        },
        PacketType::ACK => {
            let ack_packet = packet.to_specific::<AckPacket>()?;
            println!("Generic read acknowledgment packet: {}", ack_packet.path);
        },
        _ => println!("Unsupported packet type: {:?}", packet.packet_type),
    }
    
    Ok(())
}
