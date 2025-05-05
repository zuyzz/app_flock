// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{error::Error, io::{self, Write}};
use argon2::{password_hash::{rand_core::OsRng, SaltString, PasswordHash, PasswordHasher, PasswordVerifier}, Argon2};
use slint::SharedString;

slint::include_modules!();

fn main() -> Result<(), Box<dyn Error>> {
    let ui = AppWindow::new()?;

    enter_password();

    ui.on_choose_file({
        let ui_handle = ui.as_weak();
        move || {
            let ui = ui_handle.unwrap();
            ui.set_file_path(SharedString::from(choose_file().unwrap()));
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

fn enter_password() {
    let saved_pwd = b"flock0764";
    let salt = SaltString::generate(&mut OsRng);

    println!("Enter your password: ");
    io::stdout().flush().unwrap();
    let mut entered_pwd = String::new();
    io::stdin().read_line(&mut entered_pwd).unwrap();
    let entered_pwd = entered_pwd.trim_end();

    let argon2 = Argon2::default();

    let password_hash = argon2.hash_password(saved_pwd, &salt).unwrap().to_string();
    let parsed_hash = PasswordHash::new(&password_hash).unwrap();

    assert!(argon2.verify_password(entered_pwd.as_bytes(), &parsed_hash).is_ok());
    println!("Password verified successfully")
}
