// Authentication and cryptography utilities
// Phase 3: Password hashing, service key validation, encryption

pub mod password;
pub mod service_auth;
pub mod hsk;
pub mod totp;

pub use password::{hash_password, verify_password};
pub use service_auth::{extract_api_key, validate_service_key};
pub use hsk::{expected_hsk_assertion, verify_hsk_assertion};
pub use totp::{generate_totp_secret_base32, verify_totp_code};
