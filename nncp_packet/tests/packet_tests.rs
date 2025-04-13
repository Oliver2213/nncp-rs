use nncp_packet::{Error, Packet, PacketType, PacketContent};
use rand::{RngCore, Rng};
use std::io::Cursor;

/// Test creating and validating basic packet structure
#[test]
fn test_packet_creation() {
    // Test cases with different packet types, nice values, and paths
    let test_cases = vec![
        (PacketType::File, 123, "test/path/file.txt"),
        (PacketType::Freq, 50, "requested/file.dat"),
        (PacketType::Exec, 200, "echo 'hello world'"),
        (PacketType::Trns, 150, "transit/path/info"),
        (PacketType::ExecFat, 100, "complex command with args"),
        (PacketType::ACK, 75, "acknowledgment/id"),
    ];

    for (packet_type, nice, path) in test_cases {
        // Create a packet
        let packet = Packet::new(packet_type, nice, path.as_bytes())
            .expect("Failed to create packet");
        
        // Verify packet properties
        assert_eq!(packet.packet_type, packet_type);
        assert_eq!(packet.nice, nice);
        assert_eq!(packet.path_len as usize, path.len());
        assert_eq!(&packet.path[..packet.path_len as usize], path.as_bytes());
        
        // Test path accessor
        assert_eq!(packet.path(), path.as_bytes());
    }
}

/// Test serialization and deserialization of packets
#[test]
fn test_packet_serialization() {
    let test_cases = vec![
        (PacketType::File, 123, "test/path/file.txt"),
        (PacketType::Freq, 50, "requested/file.dat"),
        (PacketType::Exec, 200, "echo 'hello world'"),
    ];

    for (packet_type, nice, path) in test_cases {
        // Create a packet
        let packet = Packet::new(packet_type, nice, path.as_bytes())
            .expect("Failed to create packet");
        
        // Serialize packet
        let mut buffer = Vec::new();
        packet.encode(&mut buffer).expect("Failed to serialize packet");
        
        // Deserialize packet
        let mut cursor = Cursor::new(&buffer);
        let deserialized = Packet::decode(&mut cursor)
            .expect("Failed to deserialize packet");
        let nice_value = deserialized.nice;
        
        // Verify deserialized packet matches original
        assert_eq!(deserialized.packet_type, packet_type);
        assert_eq!(nice_value, nice);
        assert_eq!(deserialized.path_len, packet.path_len);
        assert_eq!(&deserialized.path[..deserialized.path_len as usize], path.as_bytes());
    }
}

/// Test packet content implementations (similar to Go's implementation)
#[test]
fn test_packet_content_implementations() {
    // Test File packet
    let file_path = "test/file.txt";
    let file_packet = nncp_packet::FilePacket {
        path: file_path.to_string(),
    };
    
    let nice = 123;
    let packet = file_packet.to_packet(nice).expect("Failed to convert to packet");
    
    assert_eq!(packet.packet_type, PacketType::File);
    assert_eq!(packet.nice, nice);
    assert_eq!(packet.path(), file_path.as_bytes());
    
    let recovered = nncp_packet::FilePacket::from_packet(&packet)
        .expect("Failed to convert from packet");
    assert_eq!(recovered.path, file_path);
    
    // Test Exec packet
    let command = "echo 'test command'";
    let exec_packet = nncp_packet::ExecPacket {
        command: command.to_string(),
    };
    
    let packet = exec_packet.to_packet(nice).expect("Failed to convert to packet");
    
    assert_eq!(packet.packet_type, PacketType::Exec);
    assert_eq!(packet.path(), command.as_bytes());
    
    let recovered = nncp_packet::ExecPacket::from_packet(&packet)
        .expect("Failed to convert from packet");
    assert_eq!(recovered.command, command);
}

/// Test with random data (similar to Go's TestPktEncWrite)
#[test]
fn test_packet_with_random_data() {
    let mut rng = rand::thread_rng();
    
    for _ in 0..100 {
        // Generate random path with random size
        let path_size = rng.gen_range(0..255) as usize;
        let mut path = vec![0u8; path_size];
        rng.fill_bytes(&mut path);
        
        // Filter out non-printable characters for better test output
        for byte in &mut path {
            if !(*byte as char).is_ascii_graphic() && !(*byte as char).is_ascii_whitespace() {
                *byte = b'a' + (rng.gen::<u8>() % 26);
            }
        }
        
        // Create packet with random nice value
        let nice = rng.gen::<u8>();
        let packet_type = match rng.gen_range(0..6) {
            0 => PacketType::File,
            1 => PacketType::Freq,
            2 => PacketType::Exec,
            3 => PacketType::Trns,
            4 => PacketType::ExecFat,
            _ => PacketType::ACK,
        };
        
        // Create packet
        let packet = match Packet::new(packet_type, nice, &path) {
            Ok(p) => p,
            Err(Error::PathTooLong(_)) => continue, // Skip if path too long
            Err(e) => panic!("Unexpected error: {:?}", e),
        };
        
        // Verify packet properties
        assert_eq!(packet.packet_type, packet_type);
        assert_eq!(packet.nice, nice);
        assert_eq!(packet.path_len as usize, path.len());
        assert_eq!(&packet.path[..packet.path_len as usize], &path);
        
        // Test serialization/deserialization
        let mut buffer = Vec::new();
        packet.encode(&mut buffer).expect("Failed to serialize packet");
        
        let mut cursor = Cursor::new(&buffer);
        let deserialized = Packet::decode(&mut cursor)
            .expect("Failed to deserialize packet");
        let nice_value = deserialized.nice;
        
        assert_eq!(deserialized.packet_type, packet_type);
        assert_eq!(nice_value, nice);
        assert_eq!(deserialized.path_len, packet.path_len);
        assert_eq!(&deserialized.path[..deserialized.path_len as usize], &path);
    }
}

/// Test error handling for invalid packets
#[test]
fn test_invalid_packet_handling() {
    // Test path too long
    let long_path = vec![b'a'; 256]; // Assuming MAX_PATH_SIZE is 255
    let result = Packet::new(PacketType::File, 123, &long_path);
    assert!(matches!(result, Err(Error::PathTooLong(_))));
    
    // Test invalid packet type conversion
    let packet = Packet::new(PacketType::File, 123, b"test.txt").unwrap();
    let result = nncp_packet::ExecPacket::from_packet(&packet);
    assert!(matches!(result, Err(Error::InvalidPacketType { .. })));
    
    // Test invalid magic number
    let mut buffer = Vec::new();
    let packet = Packet::new(PacketType::File, 123, b"test.txt").unwrap();
    packet.encode(&mut buffer).unwrap();
    
    // Corrupt the magic number
    buffer[0] = buffer[0].wrapping_add(1);
    
    let mut cursor = Cursor::new(&buffer);
    let result = Packet::decode(&mut cursor);
    assert!(matches!(result, Err(Error::BadMagic)));
    
    // Test invalid packet type
    let mut buffer = Vec::new();
    let packet = Packet::new(PacketType::File, 123, b"test.txt").unwrap();
    packet.encode(&mut buffer).unwrap();
    
    // Corrupt the packet type
    buffer[8] = 255; // Invalid packet type
    
    let mut cursor = Cursor::new(&buffer);
    let result = Packet::decode(&mut cursor);
    assert!(matches!(result, Err(Error::BadPacketType)));
}
