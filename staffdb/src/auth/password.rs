// Password hashing and verification using Argon2id

use crate::error::{Error, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, PasswordVerifier,
};

/// Hash a plaintext password with Argon2id
/// 
/// OWASP recommended algorithm with high work factor for security
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| {
            tracing::error!("Password hashing failed: {}", e);
            Error::InternalServerError
        })?
        .to_string();

    Ok(password_hash)
}

/// Verify a password against a stored hash
/// 
/// Constant-time comparison to prevent timing attacks
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|_| Error::ValidationError("Invalid password hash format".to_string()))?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let password = "secure_password_123!@#";
        let hash = hash_password(password).expect("hash should succeed");

        assert!(hash.len() > 0);
        assert!(hash.contains("$argon2"));

        let valid = verify_password(password, &hash).expect("verify should succeed");
        assert!(valid);

        let invalid = verify_password("wrong_password", &hash).expect("verify should succeed");
        assert!(!invalid);
    }

    #[test]
    fn test_different_passwords_produce_different_hashes() {
        let password1 = "password_one";
        let password2 = "password_two";

        let hash1 = hash_password(password1).expect("hash1 should succeed");
        let hash2 = hash_password(password2).expect("hash2 should succeed");

        assert_ne!(hash1, hash2);
    }
}
