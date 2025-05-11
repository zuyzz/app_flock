use std::sync::OnceLock;

use argon2::{password_hash::{rand_core::OsRng, SaltString, PasswordHash, PasswordHasher, PasswordVerifier}, Argon2};
use secrecy::{ExposeSecret, SecretString};

static SECRET: OnceLock<SecretString> = OnceLock::new();

pub fn store_secret(secret: &str) -> Result<(), secrecy::SecretBox<str>> {
    SECRET.set(SecretString::from(secret))
}

pub fn get_secret<'a>() -> Option<&'a str> {
    SECRET.get().map(|s| s.expose_secret())
}

pub fn hash_secret(secret: &str, secret_salt: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::from_b64(secret_salt)?;
    let secret_hash = Argon2::default().hash_password(secret.as_bytes(), &salt)?
        .to_string();

    Ok(secret_hash)
}

pub fn verify_secret(secret: &str, secret_hash: &str) -> Result<(), argon2::password_hash::Error> {
    let hash = &PasswordHash::new(secret_hash)?;
    Argon2::default().verify_password(secret.as_bytes(), hash)
}

pub fn random_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

pub fn derive_key(secret: &str, kdf_salt: &str) -> [u8; 32] {
    let mut kdf_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(secret.as_bytes(), kdf_salt.as_bytes(), &mut kdf_key)
        .expect("Key derivation failed");
    
    kdf_key
}