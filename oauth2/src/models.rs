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
    pub owner_account_id: String,
    pub collaborator_account_ids: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingConsent {
    pub request_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub scope: Vec<String>,
    pub account_id: String,
    pub account_type: String,
    pub effective_permissions: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub account_id: String,
    pub scope: Vec<String>,
    pub effective_permissions: Vec<String>,
    pub redirect_uri: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub token: String,
    pub client_id: String,
    pub account_id: String,
    pub scope: Vec<String>,
    pub effective_permissions: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub token: String,
    pub client_id: String,
    pub account_id: String,
    pub scope: Vec<String>,
    pub effective_permissions: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditEvent {
    pub id: String,
    pub actor_account_id: String,
    pub operation: String,
    pub target_type: String,
    pub target_id: String,
    pub decision: String,
    pub correlation_id: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelSession {
    pub id: String,
    pub account_id: String,
    pub permissions: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
