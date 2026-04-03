use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::models::{AccessToken, AuthorizationCode, OAuthClient, PendingConsent, RefreshToken};

#[derive(Default)]
pub struct MemoryStore {
    pub clients: HashMap<String, OAuthClient>,
    pub pending_consents: HashMap<String, PendingConsent>,
    pub auth_codes: HashMap<String, AuthorizationCode>,
    pub access_tokens: HashMap<String, AccessToken>,
    pub refresh_tokens: HashMap<String, RefreshToken>,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub store: Arc<Mutex<MemoryStore>>,
    pub http_client: reqwest::Client,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            store: Arc::new(Mutex::new(MemoryStore::default())),
            http_client: reqwest::Client::new(),
        }
    }
}

pub fn generate_secret(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn now_plus_seconds(seconds: i64) -> chrono::DateTime<Utc> {
    Utc::now() + Duration::seconds(seconds)
}
