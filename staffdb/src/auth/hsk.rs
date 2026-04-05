use sha2::{Digest, Sha256};

// Bootstrap assertion format for HSK development flow.
// Expected proof = hex(sha256("<challenge>:<credential_id>"))
pub fn expected_hsk_assertion(challenge: &str, credential_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", challenge.trim(), credential_id.trim()));
    let digest = hasher.finalize();
    hex::encode(digest)
}

pub fn verify_hsk_assertion(challenge: &str, credential_id: &str, assertion: &str) -> bool {
    expected_hsk_assertion(challenge, credential_id) == assertion.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{expected_hsk_assertion, verify_hsk_assertion};

    #[test]
    fn assertion_round_trip_is_valid() {
        let challenge = "challenge-1";
        let credential_id = "credential-abc";
        let assertion = expected_hsk_assertion(challenge, credential_id);
        assert!(verify_hsk_assertion(challenge, credential_id, &assertion));
    }

    #[test]
    fn assertion_mismatch_is_invalid() {
        let challenge = "challenge-1";
        let credential_id = "credential-abc";
        assert!(!verify_hsk_assertion(challenge, credential_id, "deadbeef"));
    }
}