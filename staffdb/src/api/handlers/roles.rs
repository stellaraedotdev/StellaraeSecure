// Role management endpoints (Phase 4)

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    db::{AuditLogRepository, RoleRepository, SqliteAuditLogRepository, SqliteRoleRepository},
    error::{Error, Result},
    AppState,
};
use crate::api::middleware::AuthenticatedService;

/// Valid role types
const VALID_ROLES: &[&str] = &["admin", "staff", "user"];

/// Role response
#[derive(Serialize)]
pub struct RoleResponse {
    pub id: String,
    pub role: String,
    pub granted_at: String,
}

/// Request to grant a role
#[derive(Deserialize)]
pub struct GrantRoleRequest {
    pub role: String,
}

/// Response listing roles
#[derive(Serialize)]
pub struct RolesListResponse {
    pub account_id: String,
    pub roles: Vec<RoleResponse>,
}

/// Path parameters for role operations
#[derive(Deserialize)]
pub struct RolePath {
    pub id: String,
    pub role: Option<String>,
}

/// Grant a role to an account
pub async fn grant_role(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedService>,
    Path(account_id): Path<String>,
    Json(payload): Json<GrantRoleRequest>,
) -> Result<(StatusCode, Json<RoleResponse>)> {
    // Validate account ID format
    Uuid::parse_str(&account_id)
        .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

    // Validate role
    if !VALID_ROLES.contains(&payload.role.as_str()) {
        return Err(Error::ValidationError(
            format!("Invalid role. Must be one of: {}", VALID_ROLES.join(", ")),
        ));
    }

    let repo = SqliteRoleRepository::new(state.db_pool.clone());

    // Check if account exists (will fail if not)
    repo.grant_role(&account_id, &payload.role).await?;

    let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
    let _ = audit_repo
        .log_event(
            &account_id,
            "role-granted",
            &caller.id,
            Some(serde_json::json!({ "role": payload.role })),
        )
        .await?;

    tracing::info!(
        account_id = %account_id,
        role = %payload.role,
        "Role granted"
    );

    let response = RoleResponse {
        id: Uuid::new_v4().to_string(),
        role: payload.role,
        granted_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Revoke a role from an account
pub async fn revoke_role(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedService>,
    Path((account_id, role)): Path<(String, String)>,
) -> Result<StatusCode> {
    // Validate account ID format
    Uuid::parse_str(&account_id)
        .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

    // Validate role
    if !VALID_ROLES.contains(&role.as_str()) {
        return Err(Error::ValidationError(
            format!("Invalid role. Must be one of: {}", VALID_ROLES.join(", ")),
        ));
    }

    let repo = SqliteRoleRepository::new(state.db_pool.clone());
    repo.revoke_role(&account_id, &role).await?;

    let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
    let _ = audit_repo
        .log_event(
            &account_id,
            "role-revoked",
            &caller.id,
            Some(serde_json::json!({ "role": role })),
        )
        .await?;

    tracing::info!(
        account_id = %account_id,
        role = %role,
        "Role revoked"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Get all roles for an account
pub async fn get_roles(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<String>,
) -> Result<Json<RolesListResponse>> {
    // Validate account ID format
    Uuid::parse_str(&account_id)
        .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

    let repo = SqliteRoleRepository::new(state.db_pool.clone());
    let roles = repo.get_roles(&account_id).await?;

    let response = RolesListResponse {
        account_id,
        roles: roles
            .into_iter()
            .map(|r| RoleResponse {
                id: r.id,
                role: r.role,
                granted_at: r.granted_at.to_rfc3339(),
            })
            .collect(),
    };

    Ok(Json(response))
}
