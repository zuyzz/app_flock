// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{error::Error, fs, io::{self, Write}};
use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, KeyInit, Nonce};
use argon2::{password_hash::{rand_core::OsRng, SaltString, PasswordHash, PasswordHasher, PasswordVerifier}, Argon2};
use rand_core::RngCore;
use slint::SharedString;

slint::include_modules!();

fn main() -> Result<(), Box<dyn Error>> {
    let ui = AppWindow::new()?;

    // save into file later
    let saved_pwd = b"flock0764";
    let salt = SaltString::generate(&mut OsRng);

    let file_path = "C:\\Users\\Admin\\Downloads\\aventure96.png";

    let pwd = enter_password();
    verified_password(&pwd, saved_pwd, salt.clone());

    let key = generate_key(pwd.as_bytes(), &salt.as_str().as_bytes());
    let content = read_file_content(file_path);
    let (encrypted_content, nonce_bytes) = encrypt(&key, &content);
    println!("Encrypting at {}", file_path);
    let decrypted_content = decrypt(&key, &encrypted_content, &nonce_bytes);
    assert!(content == decrypted_content);
    println!("Decrypting success!");

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
            
        }
    });

    ui.on_decrypt({
        let ui_handle = ui.as_weak();
        move || {
            let ui = ui_handle.unwrap();
            
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

fn encrypt(key: &[u8; 32], content: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12]; // 96-bit nonce
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_content = cipher.encrypt(&nonce, content)
        .expect("encryption failed");
    (encrypted_content, nonce_bytes)
}

fn decrypt(key: &[u8; 32], encrypted_content: &[u8], nonce_bytes: &[u8; 12]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce= Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, encrypted_content)
        .expect("decryption failed")
}