// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::File;
use std::io::Read;
use std::{error::Error, io::Write};
use flock::crypto::{decrypt, encrypt};
use flock::secure::{hash_secret, random_salt, store_secret, verify_secret};
use flock::utils::file::{get_file_extension, get_path, open_temp_file, read_file_content, select_file, write_file_content};
use serde::{Deserialize, Serialize};
use slint::{SharedString, Weak};

slint::include_modules!();

fn main() -> Result<(), Box<dyn Error>> {
    let auth = AuthWindow::new()?;
    let app = AppWindow::new()?;

    let auth_handle = auth.as_weak();
    let app_handle = app.as_weak();

    auth.on_authenticate({
        let auth = Weak::clone(&auth_handle).unwrap();
        let app = Weak::clone(&app_handle).unwrap();
        move |secret| {
            if let Ok(auth_data) = load_auth_data() {
                // log in
                if let Ok(_) = verify_secret(secret.as_str(), &auth_data.secret_hash) {
                    store_secret(secret.as_str());
                    app.show().unwrap();
                    auth.hide().unwrap();
                }
            }
            else {
                // register
                let salt = random_salt();
                if let Ok(_) = save_auth_data(secret.as_str(), salt.as_str()) {
                    store_secret(secret.as_str());
                    app.show().unwrap();
                    auth.hide().unwrap();
                }
            }
        }
    });
    
    app.on_choose_file({
        let app = Weak::clone(&app_handle).unwrap();
        move || {
            if let Some(file) = select_file() {
                let file_path = get_path(&file);
                app.set_current_file_path(SharedString::from(file_path));
            }
        }
    });

    app.on_open_file({
        let app = Weak::clone(&app_handle).unwrap();
        move || {
            let file_path = app.get_current_file_path();
            let file_path = file_path.as_str();
            let extension = get_file_extension(file_path).unwrap_or(String::new());
            
            let data = read_file_content(file_path);
            if let Ok(decrypt_data) = decrypt(&data) {
                open_temp_file(&decrypt_data, &extension);
            } else {
                open_temp_file(&data, &extension);
            }
        }
    });
    
    app.on_lock_file({
        let app = Weak::clone(&app_handle).unwrap();
        move || {
            let file_path = app.get_current_file_path();
            let file_content = read_file_content(file_path.as_str());

            if let Ok(encrypted_data) = encrypt(&file_content) {
                write_file_content(&file_path, &encrypted_data);
            }
        }
    });
    
    app.on_unlock_file({
        let app = Weak::clone(&app_handle).unwrap();
        move || {
            let file_path = app.get_current_file_path();
            let file_content = read_file_content(file_path.as_str());

            if let Ok(decrypted_content) = decrypt(&file_content) {
                write_file_content(&file_path, &decrypted_content);
            }
        }
    });

    auth.run()?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthData {
    secret_hash: String, 
    salt: String,
}

fn save_auth_data(secret: &str, salt: &str) -> std::io::Result<()> {
    let password_hash = hash_secret(secret, salt)
        .unwrap();
    let salt = String::from(salt);
    let auth_data = AuthData {
        secret_hash: password_hash,
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