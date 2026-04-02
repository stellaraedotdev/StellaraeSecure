// Integration tests for staffdb

#[cfg(test)]
mod tests {
    use stellarae_staffdb::auth::password::{hash_password, verify_password};
    use stellarae_staffdb::auth::service_auth::extract_api_key;

    // Password hashing tests
    #[test]
    fn test_password_hashing_integration() {
        let password = "test_password_123!@";
        let hash = hash_password(password).expect("hash should succeed");
        let valid = verify_password(password, &hash).expect("verify should succeed");
        assert!(valid);
    }

    #[test]
    fn test_invalid_password() {
        let password = "correct_password";
        let hash = hash_password(password).expect("hash should succeed");
        let invalid = verify_password("wrong_password", &hash).expect("verify should succeed");
        assert!(!invalid);
    }

    #[test]
    fn test_password_uniqueness() {
        let password = "same_password";
        let hash1 = hash_password(password).expect("hash1 should succeed");
        let hash2 = hash_password(password).expect("hash2 should succeed");
        // Hashes should be different due to random salts
        assert_ne!(hash1, hash2);
        // But both should verify the same password
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());
    }

    // Service authentication tests
    #[test]
    fn test_extract_api_key_valid_bearer() {
        let header = "Bearer test-key-123";
        let result = extract_api_key(header);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-key-123");
    }

    #[test]
    fn test_extract_api_key_invalid_format() {
        let header = "Basic test-key";
        let result = extract_api_key(header);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_api_key_empty_bearer() {
        let header = "Bearer ";
        let result = extract_api_key(header);
        assert!(result.is_err());
    }

    #[test]
    fn test_password_minimum_length() {
        let short_password = "short";
        let hash = hash_password(short_password).expect("hash should work even for short passwords");
        let valid = verify_password(short_password, &hash).expect("verify should succeed");
        assert!(valid);
    }

    #[test]
    fn test_password_special_characters() {
        let password = "P@ssw0rd!#$%^&*()_+-=[]{}|;:',.<>?/";
        let hash = hash_password(password).expect("hash should handle special chars");
        let valid = verify_password(password, &hash).expect("verify should succeed");
        assert!(valid);
    }

    #[test]
    fn test_password_unicode() {
        let password = "بل میں آپ کو🚀مثال دیتا ہوں";
        let hash = hash_password(password).expect("hash should handle unicode");
        let valid = verify_password(password, &hash).expect("verify should succeed");
        assert!(valid);
    }
}
