use nncp_packet::{EBlob, DEFAULT_S, DEFAULT_T, DEFAULT_P};
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Data to encrypt
    let data = b"This is a secret message that will be encrypted in an EBlob.";
    
    // Password for encryption
    let password = b"my_secure_password";
    
    println!("Original data: {}", String::from_utf8_lossy(data));
    
    // Create an encrypted blob with default parameters
    let encrypted = EBlob::new(DEFAULT_S, DEFAULT_T, DEFAULT_P, password, data)?;
    
    println!("Encrypted blob size: {} bytes", encrypted.len());
    
    // Save the encrypted blob to a file
    std::fs::write("encrypted.blob", &encrypted)?;
    println!("Encrypted blob saved to 'encrypted.blob'");
    
    // Decrypt the blob
    let decrypted = EBlob::decrypt(&encrypted, password)?;
    
    println!("Decrypted data: {}", String::from_utf8_lossy(&decrypted));
    
    // Verify the decrypted data matches the original
    assert_eq!(decrypted, data);
    println!("Decryption successful - data matches original!");
    
    // Try with wrong password (this should fail)
    println!("\nTrying with wrong password:");
    match EBlob::decrypt(&encrypted, b"wrong_password") {
        Ok(_) => println!("Unexpectedly decrypted with wrong password!"),
        Err(e) => println!("Failed as expected: {}", e),
    }
    
    Ok(())
}
