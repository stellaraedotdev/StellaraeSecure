use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret_hash: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub audience: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct PendingConsent {
    pub request_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub scope: Vec<String>,
    pub account_id: String,
    pub account_type: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub account_id: String,
    pub scope: Vec<String>,
    pub redirect_uri: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AccessToken {
    pub token: String,
    pub client_id: String,
    pub account_id: String,
    pub scope: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub token: String,
    pub client_id: String,
    pub account_id: String,
    pub scope: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}
