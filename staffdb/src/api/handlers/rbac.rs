use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::api::middleware::AuthenticatedService;
use crate::db::{
    AuditLogRepository,
    RbacRepository,
    SqliteAuditLogRepository,
    SqliteRbacRepository,
};
use crate::error::{Error, Result};
use crate::models::{
    AssignPermissionToRoleRequest,
    AssignRoleToAccountRequest,
    CreatePermissionRequest,
    CreateRbacRoleRequest,
};
use crate::AppState;

#[derive(Serialize)]
pub struct RbacRoleResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
pub struct PermissionResponse {
    pub id: String,
    pub permission_key: String,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct AccountRoleAssignmentResponse {
    pub id: String,
    pub account_id: String,
    pub role_id: String,
    pub granted_by: Option<String>,
    pub granted_at: String,
}

#[derive(Serialize)]
pub struct EffectivePermissionsResponse {
    pub account_id: String,
    pub permissions: Vec<String>,
}

pub async fn create_role(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedService>,
    Json(payload): Json<CreateRbacRoleRequest>,
) -> Result<(StatusCode, Json<RbacRoleResponse>)> {
    let name = payload.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(Error::ValidationError(
            "Role name must be between 1 and 128 characters".to_string(),
        ));
    }

    let repo = SqliteRbacRepository::new(state.db_pool.clone());
    let role = repo
        .create_rbac_role(name, payload.description.as_deref(), payload.is_system.unwrap_or(false))
        .await?;

    let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
    let _ = audit_repo
        .log_event(
            &caller.id,
            "rbac-role-created",
            &caller.id,
            Some(serde_json::json!({
                "role_id": role.id,
                "name": role.name,
                "is_system": role.is_system,
            })),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(RbacRoleResponse {
            id: role.id,
            name: role.name,
            description: role.description,
            is_system: role.is_system,
            created_at: role.created_at.to_rfc3339(),
            updated_at: role.updated_at.to_rfc3339(),
        }),
    ))
}

pub async fn list_roles(State(state): State<Arc<AppState>>) -> Result<Json<Vec<RbacRoleResponse>>> {
    let repo = SqliteRbacRepository::new(state.db_pool.clone());
    let roles = repo.list_rbac_roles().await?;

    Ok(Json(
        roles
            .into_iter()
            .map(|role| RbacRoleResponse {
                id: role.id,
                name: role.name,
                description: role.description,
                is_system: role.is_system,
                created_at: role.created_at.to_rfc3339(),
                updated_at: role.updated_at.to_rfc3339(),
            })
            .collect(),
    ))
}

pub async fn create_permission(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedService>,
    Json(payload): Json<CreatePermissionRequest>,
) -> Result<(StatusCode, Json<PermissionResponse>)> {
    let key = payload.permission_key.trim();
    if key.is_empty() || key.len() > 255 {
        return Err(Error::ValidationError(
            "Permission key must be between 1 and 255 characters".to_string(),
        ));
    }

    let repo = SqliteRbacRepository::new(state.db_pool.clone());
    let permission = repo
        .create_permission(key, payload.description.as_deref())
        .await?;

    let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
    let _ = audit_repo
        .log_event(
            &caller.id,
            "rbac-permission-created",
            &caller.id,
            Some(serde_json::json!({
                "permission_id": permission.id,
                "permission_key": permission.permission_key,
            })),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(PermissionResponse {
            id: permission.id,
            permission_key: permission.permission_key,
            description: permission.description,
            created_at: permission.created_at.to_rfc3339(),
        }),
    ))
}

pub async fn list_permissions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PermissionResponse>>> {
    let repo = SqliteRbacRepository::new(state.db_pool.clone());
    let permissions = repo.list_permissions().await?;

    Ok(Json(
        permissions
            .into_iter()
            .map(|permission| PermissionResponse {
                id: permission.id,
                permission_key: permission.permission_key,
                description: permission.description,
                created_at: permission.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}

pub async fn assign_permission_to_role(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedService>,
    Path(role_id): Path<String>,
    Json(payload): Json<AssignPermissionToRoleRequest>,
) -> Result<StatusCode> {
    Uuid::parse_str(&role_id)
        .map_err(|_| Error::ValidationError("Invalid role ID format".to_string()))?;
    Uuid::parse_str(&payload.permission_id)
        .map_err(|_| Error::ValidationError("Invalid permission ID format".to_string()))?;

    let repo = SqliteRbacRepository::new(state.db_pool.clone());
    repo.assign_permission_to_role(&role_id, &payload.permission_id)
        .await?;

    let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
    let _ = audit_repo
        .log_event(
            &caller.id,
            "rbac-role-permission-assigned",
            &caller.id,
            Some(serde_json::json!({
                "role_id": role_id,
                "permission_id": payload.permission_id,
            })),
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn assign_role_to_account(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedService>,
    Path(account_id): Path<String>,
    Json(payload): Json<AssignRoleToAccountRequest>,
) -> Result<(StatusCode, Json<AccountRoleAssignmentResponse>)> {
    Uuid::parse_str(&account_id)
        .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;
    Uuid::parse_str(&payload.role_id)
        .map_err(|_| Error::ValidationError("Invalid role ID format".to_string()))?;

    let repo = SqliteRbacRepository::new(state.db_pool.clone());
    let assignment = repo
        .assign_role_to_account(&account_id, &payload.role_id, Some(&caller.id))
        .await?;

    let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
    let _ = audit_repo
        .log_event(
            &account_id,
            "rbac-account-role-assigned",
            &caller.id,
            Some(serde_json::json!({
                "role_id": payload.role_id,
            })),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(AccountRoleAssignmentResponse {
            id: assignment.id,
            account_id: assignment.account_id,
            role_id: assignment.role_id,
            granted_by: assignment.granted_by,
            granted_at: assignment.granted_at.to_rfc3339(),
        }),
    ))
}

pub async fn revoke_role_from_account(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedService>,
    Path((account_id, role_id)): Path<(String, String)>,
) -> Result<StatusCode> {
    Uuid::parse_str(&account_id)
        .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;
    Uuid::parse_str(&role_id)
        .map_err(|_| Error::ValidationError("Invalid role ID format".to_string()))?;

    let repo = SqliteRbacRepository::new(state.db_pool.clone());
    repo.revoke_role_from_account(&account_id, &role_id).await?;

    let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
    let _ = audit_repo
        .log_event(
            &account_id,
            "rbac-account-role-revoked",
            &caller.id,
            Some(serde_json::json!({
                "role_id": role_id,
            })),
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_account_roles(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<String>,
) -> Result<Json<Vec<AccountRoleAssignmentResponse>>> {
    Uuid::parse_str(&account_id)
        .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

    let repo = SqliteRbacRepository::new(state.db_pool.clone());
    let assignments = repo.list_account_roles(&account_id).await?;

    Ok(Json(
        assignments
            .into_iter()
            .map(|assignment| AccountRoleAssignmentResponse {
                id: assignment.id,
                account_id: assignment.account_id,
                role_id: assignment.role_id,
                granted_by: assignment.granted_by,
                granted_at: assignment.granted_at.to_rfc3339(),
            })
            .collect(),
    ))
}

pub async fn get_effective_permissions(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<String>,
) -> Result<Json<EffectivePermissionsResponse>> {
    Uuid::parse_str(&account_id)
        .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

    let repo = SqliteRbacRepository::new(state.db_pool.clone());
    let permissions = repo.get_effective_permissions(&account_id).await?;

    Ok(Json(EffectivePermissionsResponse {
        account_id,
        permissions,
    }))
}
