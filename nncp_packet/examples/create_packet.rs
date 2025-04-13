//! Example showing how to create and encode different NNCP packet types

use std::fs::File;
use std::io::BufWriter;
use nncp_packet::{FilePacket, ExecPacket, FreqPacket, TrnsPacket, AckPacket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a file packet
    let file_packet = FilePacket::new("/path/to/file.txt")?;
    let file = File::create("file_packet.bin")?;
    let mut writer = BufWriter::new(file);
    let bytes_written = file_packet.encode(&mut writer, 10)?;
    println!("Wrote file packet: {} bytes", bytes_written);
    
    // Create an exec packet
    let exec_packet = ExecPacket::new("echo 'Hello, world!'")?;
    let file = File::create("exec_packet.bin")?;
    let mut writer = BufWriter::new(file);
    let bytes_written = exec_packet.encode(&mut writer, 20)?;
    println!("Wrote exec packet: {} bytes", bytes_written);
    
    // Create a freq packet
    let freq_packet = FreqPacket::new("/path/to/requested/file.txt")?;
    let file = File::create("freq_packet.bin")?;
    let mut writer = BufWriter::new(file);
    let bytes_written = freq_packet.encode(&mut writer, 30)?;
    println!("Wrote freq packet: {} bytes", bytes_written);
    
    // Create a transit packet
    let trns_packet = TrnsPacket::new("node1/node2/node3")?;
    let file = File::create("trns_packet.bin")?;
    let mut writer = BufWriter::new(file);
    let bytes_written = trns_packet.encode(&mut writer, 40)?;
    println!("Wrote transit packet: {} bytes", bytes_written);
    
    // Create an acknowledgment packet
    let ack_packet = AckPacket::new("tx-12345")?;
    let file = File::create("ack_packet.bin")?;
    let mut writer = BufWriter::new(file);
    let bytes_written = ack_packet.encode(&mut writer, 50)?;
    println!("Wrote acknowledgment packet: {} bytes", bytes_written);
    
    Ok(())
}
