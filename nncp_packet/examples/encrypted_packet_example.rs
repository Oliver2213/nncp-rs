use nncp_packet::{EncryptedPacket, FilePacket, DEFAULT_S, DEFAULT_T, DEFAULT_P};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a file packet
    let file_packet = FilePacket {
        path: "example/file.txt".to_string(),
    };
    
    // Convert to a plain packet with niceness level 5
    let packet = file_packet.to_packet(5)?;
    println!("Original packet: {:?}", packet);
    
    // Password for encryption
    let password = b"secure_password";
    
    // Create an encrypted packet with default parameters
    let encrypted = EncryptedPacket::new(&packet, password, DEFAULT_S, DEFAULT_T, DEFAULT_P)?;
    println!("Encrypted packet size: {} bytes", encrypted.encrypted_data.len());
    
    // Save the encrypted packet to a file
    std::fs::write("encrypted_packet.bin", &encrypted.encrypted_data)?;
    println!("Encrypted packet saved to 'encrypted_packet.bin'");
    
    // Decrypt the packet
    let decrypted = encrypted.decrypt(password)?;
    println!("Decrypted packet: {:?}", decrypted);
    
    // Verify the decrypted packet matches the original
    assert_eq!(decrypted.packet_type, packet.packet_type);
    assert_eq!(decrypted.nice, packet.nice);
    assert_eq!(decrypted.path_len, packet.path_len);
    assert_eq!(&decrypted.path[..decrypted.path_len as usize], 
              &packet.path[..packet.path_len as usize]);
    println!("Decryption successful - packet matches original!");
    
    // Decrypt directly to a FilePacket
    let (file_packet_decrypted, nice) = encrypted.decrypt_as::<FilePacket>(password)?;
    println!("Decrypted file packet: path={}, nice={}", file_packet_decrypted.path, nice);
    
    // Try with wrong password (this should fail)
    println!("\nTrying with wrong password:");
    match encrypted.decrypt(b"wrong_password") {
        Ok(_) => println!("Unexpectedly decrypted with wrong password!"),
        Err(e) => println!("Failed as expected: {}", e),
    }
    
    Ok(())
}
