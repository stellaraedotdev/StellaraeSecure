// Domain models for staffdb
// Serializable structs for accounts, roles, and audit events

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Account represents a user or staff member in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Unique account identifier (UUID)
    pub id: String,

    /// Username for login (unique, immutable)
    pub username: String,

    /// Email address (unique)
    pub email: String,

    /// Password hash (Argon2id, populated in Phase 3)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,

    /// Account is active and can authenticate
    pub is_active: bool,

    /// Account type: 'staff' or 'user'
    pub account_type: String,

    /// Creation timestamp (UTC)
    pub created_at: DateTime<Utc>,

    /// Last update timestamp (UTC)
    pub updated_at: DateTime<Utc>,
}

/// Role represents a permission grant for an account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique role grant identifier
    pub id: String,

    /// Role name: 'admin', 'staff', or 'user'
    pub role: String,

    /// When the role was granted (UTC)
    pub granted_at: DateTime<Utc>,
}

/// AuditEvent represents an immutable log entry for account changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier
    pub id: String,

    /// Account that was affected
    pub account_id: String,

    /// Action performed: create, update, delete, role-grant, role-revoke, etc.
    pub action: String,

    /// Service that performed the action
    pub actor_service: String,

    /// Additional context as JSON (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    /// When the event occurred (UTC)
    pub timestamp: DateTime<Utc>,
}

// Request/Response DTOs for API (will be populated in Phase 4)

/// Request to create a new account
#[derive(Debug, Deserialize)]
pub struct CreateAccountRequest {
    pub username: String,
    pub email: String,
    pub account_type: Option<String>, // 'staff' or 'user', defaults to 'user'
}

/// Request to update an account
#[derive(Debug, Deserialize)]
pub struct UpdateAccountRequest {
    pub email: Option<String>,
    pub is_active: Option<bool>,
}

/// Request to grant a role
#[derive(Debug, Deserialize)]
pub struct GrantRoleRequest {
    pub role: String, // 'admin', 'staff', or 'user'
}

/// Standard API response wrapper
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub data: Option<T>,
    pub error: Option<String>,
    pub status: u16,
}
