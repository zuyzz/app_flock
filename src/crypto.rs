use std::error::Error;

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};

use crate::secure::{derive_key, get_secret, random_salt};

const MAGIC_HEADER: &[u8] = b"flock";

pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if &data[..MAGIC_HEADER.len()] == MAGIC_HEADER {
        return Err("Already encrypted".into());
    }
    
    let secret = get_secret().ok_or("Secret not initialized")?;
    let kdf_salt = random_salt();
    let kdf_key = derive_key(secret, kdf_salt.as_str());
    let cipher = Aes256Gcm::new(&kdf_key.into());

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_content = cipher.encrypt(&nonce, data)
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let salt_str = kdf_salt.as_str();
    let salt_len = salt_str.len();
    if salt_len > u8::MAX as usize {
        return Err("Salt too long".into());
    }

    let mut result = Vec::new();
    result.extend_from_slice(MAGIC_HEADER);
    result.extend_from_slice(&nonce_bytes);
    result.push(salt_len as u8);
    result.extend_from_slice(&kdf_salt.as_str().as_bytes());
    result.extend_from_slice(&encrypted_content);

    Ok(result)
}

pub fn decrypt(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let header_len: usize = MAGIC_HEADER.len();
    let nonce_len: usize = 12;

    if data.len() < header_len + nonce_len + 1 {
        return Err("Data too short".into()); 
    }

    if &data[..header_len] != MAGIC_HEADER {
        return Err("Invalid header".into());
    }

    let nonce_start = header_len;
    let nonce_end = nonce_start + nonce_len;
    let nonce_bytes: [u8; 12] = data[nonce_start..nonce_end]
        .try_into()
        .map_err(|_| "Failed to read nonce")?;

    let salt_len_index = nonce_end;
    let salt_len = data[salt_len_index] as usize;

    let salt_start = salt_len_index + 1;
    let salt_end = salt_start + salt_len;

    if data.len() < salt_end {
        return Err("Data too short for salt".into());
    }

    let salt = std::str::from_utf8(&data[salt_start..salt_end])
        .map_err(|_| "Salt not valid UTF-8")?;

    let encrypted_content = &data[salt_end..];

    let secret = get_secret().ok_or("Secret not initialized")?;
    let key = derive_key(secret, salt);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce= Nonce::from_slice(&nonce_bytes);
    
    let content = cipher
        .decrypt(nonce, encrypted_content)
        .map_err(|e| format!("Decryption failed: {e}"))?;

    Ok(content)
}