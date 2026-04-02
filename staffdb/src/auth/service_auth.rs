// Service-to-service authentication via API keys

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use hex;

/// Validate a service API key against configured allow-list.
pub fn validate_service_key(provided_key: &str, allowed_keys: &[String]) -> Result<()> {
    if provided_key.is_empty() {
        return Err(Error::AuthenticationError(
            "Service key is required".to_string(),
        ));
    }

    if allowed_keys.is_empty() {
        return Err(Error::AuthenticationError(
            "No service API keys are configured".to_string(),
        ));
    }

    let is_valid = allowed_keys
        .iter()
        .any(|k| constant_time_eq(provided_key.as_bytes(), k.as_bytes()));

    if !is_valid {
        return Err(Error::AuthenticationError("Invalid service key".to_string()));
    }

    tracing::info!(key_hash = %hash_key(provided_key), "Service key validated");
    Ok(())
}

/// Hash a key for logging (never log the actual key)
fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Expected format for Authorization header
pub const BEARER_PREFIX: &str = "Bearer ";

/// Extract API key from Authorization header
pub fn extract_api_key(auth_header: &str) -> Result<String> {
    if let Some(key) = auth_header.strip_prefix(BEARER_PREFIX) {
        let key = key.trim();
        if key.is_empty() {
            return Err(Error::AuthenticationError(
                "Bearer token cannot be empty".to_string(),
            ));
        }
        Ok(key.to_string())
    } else {
        Err(Error::AuthenticationError(
            "Authorization header must use Bearer token format".to_string(),
        ))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_service_key() {
        let key = "test-service-key-12345";
        let result = validate_service_key(key, &[key.to_string()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_empty_key_fails() {
        let result = validate_service_key("", &["x".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_service_key_fails() {
        let result = validate_service_key("bad", &["good".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_api_key() {
        let header = "Bearer my-secret-key";
        let result = extract_api_key(header);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "my-secret-key");
    }

    #[test]
    fn test_extract_api_key_invalid_format() {
        let header = "Basic my-secret-key";
        let result = extract_api_key(header);
        assert!(result.is_err());
    }
}
