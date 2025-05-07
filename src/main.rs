// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::File;
use std::io::Read;
use std::{error::Error, fs, io::{self, Write}};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use argon2::{password_hash::{rand_core::OsRng, SaltString, PasswordHash, PasswordHasher, PasswordVerifier}, Argon2};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use slint::SharedString;

slint::include_modules!();

const MAGIC_HEADER: &[u8] = b"flock";

fn main() -> Result<(), Box<dyn Error>> {
    let auth = AuthWindow::new()?;
    let app = AppWindow::new()?;
    
    // save into file later
    // let saved_pwd = b"flock0764";
    // let salt = SaltString::generate(&mut OsRng);
    
    auth.on_authenticate({
        let auth_handle = auth.as_weak();
        let app_handle = app.as_weak();
        
        move |password| {
            let app = app_handle.upgrade().unwrap();
            let auth = auth_handle.upgrade().unwrap();
            
            match load_auth_data() {
                Ok(auth_data) => {
                    if verify_password(password.as_str(), &auth_data) {
                        app.show().unwrap();
                        auth.hide().unwrap();
                    }
                },
                Err(_) => {
                    let salt = SaltString::generate(&mut OsRng);
                    save_auth_data(password.as_str(), salt.as_str());
                    app.show().unwrap();
                    auth.hide().unwrap();
                }
            }
        }
    });
    
    app.on_choose_file({
        let app_handle = app.as_weak();
        
        move || {
            let app = app_handle.unwrap();
            app.set_file_path(SharedString::from(choose_file().unwrap()));
        }
    });
    
    app.on_encrypt({
        let app_handle = app.as_weak();
        
        move || {
            let app = app_handle.unwrap();
            
            let file_path = app.get_file_path().to_string();
            let file_content = read_file_content(&file_path);
            let key = generate_key(&load_auth_data().unwrap());
            if let Ok(encrypted_content) = encrypt(&key, &file_content) {
                write_file_content(&file_path, &encrypted_content);
            }
        }
    });
    
    app.on_decrypt({
        let app_handle = app.as_weak();
        
        move || {
            let app = app_handle.unwrap();
            
            let file_path = app.get_file_path().to_string();
            let file_content = read_file_content(&file_path);
            let key = generate_key(&load_auth_data().unwrap());
            if let Ok(decrypted_content) = decrypt(&key, &file_content) {
                write_file_content(&file_path, &decrypted_content);
            }
        }
    });

    auth.run()?;

    Ok(())
}

fn choose_file() -> Option<String> {
    if let Some(file) = rfd::FileDialog::new().pick_file() {
        Some(file.display().to_string())
    } else {
        None
    }
}

// fn enter_password() -> String {
//     println!("Enter your password: ");
//     io::stdout().flush().unwrap();
//     let mut entered_pwd = String::new();
//     io::stdin().read_line(&mut entered_pwd).unwrap();
//     entered_pwd.trim_end().to_string()
// }

fn hash_password(password: & str, salt: & SaltString) -> Result<String, argon2::password_hash::Error> {
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), salt).unwrap().to_string();

    Ok(password_hash)
}

fn verify_password(password: &str, auth_data: &AuthData) -> bool {
    let argon2 = Argon2::default();
    argon2.verify_password(password.as_bytes(), &PasswordHash::new(&auth_data.password_hash).unwrap())
        .is_ok()
}

fn generate_key(auth_data: &AuthData) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(auth_data.password_hash.as_bytes(), auth_data.salt.as_bytes(), &mut key)
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

#[derive(Debug, Serialize, Deserialize)]
struct AuthData {
    password_hash: String, 
    salt: String,
}

fn save_auth_data(password: &str, salt: &str) -> std::io::Result<()> {
    let password_hash = hash_password(password, &SaltString::from_b64(salt).unwrap())
        .unwrap();
    let salt = String::from(salt);
    let auth_data = AuthData {
        password_hash,
        salt,
    };

    // Serialize to JSON
    let json = serde_json::to_string(&auth_data).unwrap();

    // Write to file
    let mut file = File::create("auth_data.json")?;
    file.write_all(json.as_bytes())?;

    Ok(())
}

fn load_auth_data() -> std::io::Result<AuthData> {
    let mut file = File::open("auth_data.json")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Deserialize JSON to UserData
    let auth_data: AuthData = serde_json::from_str(&contents).unwrap();

    Ok(auth_data)
}