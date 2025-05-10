use std::error::Error;

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};

const MAGIC_HEADER: &[u8] = b"flock";

pub fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if &data[..MAGIC_HEADER.len()] == MAGIC_HEADER {
        return Err("Already encrypted".into());
    }
    
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_content = cipher.encrypt(&nonce, data)
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let mut result = Vec::new();
    result.extend_from_slice(MAGIC_HEADER);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&encrypted_content);

    Ok(result)
}

pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let header_length: usize = MAGIC_HEADER.len();
    let nonce_length: usize = 12;
    let min_length = header_length + nonce_length;

    if data.len() < min_length {
        return Err("Data too short".into()); 
    }

    if &data[..header_length] != MAGIC_HEADER {
        return Err("Invalid header".into());
    }

    let nonce_bytes: [u8; 12] = data[header_length..min_length]
        .try_into()
        .map_err(|e| format!("Invalid nonce bytes: {e}"))?;
    let encrypted_content = &data[min_length..];

    let cipher = Aes256Gcm::new(key.into());
    let nonce= Nonce::from_slice(&nonce_bytes);
    
    let content = cipher
        .decrypt(nonce, encrypted_content)
        .map_err(|e| format!("Decryption failed: {e}"))?;

    Ok(content)
}