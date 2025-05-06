// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::File;
use std::{error::Error, fs, io::{self, Write}};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use argon2::{password_hash::{rand_core::OsRng, SaltString, PasswordHash, PasswordHasher, PasswordVerifier}, Argon2};
use rand_core::RngCore;
use slint::SharedString;

slint::include_modules!();

const MAGIC_HEADER: &[u8; 5] = b"flock";

fn main() -> Result<(), Box<dyn Error>> {
    let ui = AppWindow::new()?;

    // save into file later
    let saved_pwd = b"flock0764";
    let salt = SaltString::generate(&mut OsRng);

    let pwd = enter_password();
    verified_password(&pwd, saved_pwd, salt.clone());

    let key = generate_key(pwd.as_bytes(), &salt.as_str().as_bytes());

    ui.on_choose_file({
        let ui_handle = ui.as_weak();
        move || {
            let ui = ui_handle.unwrap();
            ui.set_file_path(SharedString::from(choose_file().unwrap()));
        }
    });

    ui.on_encrypt({
        let ui_handle = ui.as_weak();
        move || {
            let ui = ui_handle.unwrap();
            let file_path = ui.get_file_path().to_string();
            let file_content = read_file_content(&file_path);
            if let Ok(encrypted_content) = encrypt(&key, &file_content) {
                write_file_content(&file_path, &encrypted_content);
            }
        }
    });
    
    ui.on_decrypt({
        let ui_handle = ui.as_weak();
        move || {
            let ui = ui_handle.unwrap();
            let file_path = ui.get_file_path().to_string();
            let file_content = read_file_content(&file_path);
            if let Ok(decrypted_content) = decrypt(&key, &file_content) {
                write_file_content(&file_path, &decrypted_content);
            }
        }
    });

    ui.run()?;

    Ok(())
}

fn choose_file() -> Option<String> {
    if let Some(file) = rfd::FileDialog::new().pick_file() {
        Some(file.display().to_string())
    } else {
        None
    }
}

fn enter_password() -> String {
    println!("Enter your password: ");
    io::stdout().flush().unwrap();
    let mut entered_pwd = String::new();
    io::stdin().read_line(&mut entered_pwd).unwrap();
    entered_pwd.trim_end().to_string()
}

fn verified_password(password: &str, saved_pwd: &[u8], salt: SaltString) {
    let argon2 = Argon2::default();

    let password_hash = argon2.hash_password(saved_pwd, &salt).unwrap().to_string();
    let parsed_hash = PasswordHash::new(&password_hash).unwrap();

    assert!(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok());
    println!("Password verified successfully")
}

fn generate_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password, salt, &mut key)
        .expect("Key derivation failed");
    key
}

fn read_file_content(file_path: &str) -> Vec<u8> {
    fs::read(file_path).expect("Failed to read file")
}

fn write_file_content(file_path: &str, data: &[u8]) {
    let mut file = File::create(file_path).expect("Failed to create file");
    file.write_all(data).expect("Failed to write data");
}

fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
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

fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
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