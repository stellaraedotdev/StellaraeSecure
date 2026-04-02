// Account management endpoints (Phase 4)

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    auth::hash_password,
    db::{AccountRepository, AuditLogRepository, SqliteAccountRepository, SqliteAuditLogRepository},
    error::{Error, Result},
    models::{Account, UpdateAccountRequest},
    AppState,
};
use crate::api::middleware::AuthenticatedService;

/// Response wrapper for single account
#[derive(Serialize)]
pub struct AccountResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub is_active: bool,
    pub account_type: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Account> for AccountResponse {
    fn from(account: Account) -> Self {
        Self {
            id: account.id,
            username: account.username,
            email: account.email,
            is_active: account.is_active,
            account_type: account.account_type,
            created_at: account.created_at.to_rfc3339(),
            updated_at: account.updated_at.to_rfc3339(),
        }
    }
}

/// Lookup query parameters
#[derive(Deserialize)]
pub struct LookupQuery {
    pub email: Option<String>,
    pub username: Option<String>,
}

/// Create account with password (request body)
#[derive(Deserialize)]
pub struct CreateAccountWithPasswordRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub account_type: Option<String>,
}

/// Create a new account
pub async fn create_account(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedService>,
    Json(payload): Json<CreateAccountWithPasswordRequest>,
) -> Result<(StatusCode, Json<AccountResponse>)> {
    // Validate input
    if payload.username.is_empty() || payload.username.len() > 255 {
        return Err(Error::ValidationError(
            "Username must be 1-255 characters".to_string(),
        ));
    }

    if payload.email.is_empty() || payload.email.len() > 255 {
        return Err(Error::ValidationError("Invalid email".to_string()));
    }

    if payload.password.len() < 8 {
        return Err(Error::ValidationError(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    let requested_account_type = payload.account_type.as_deref().unwrap_or("user");
    if !["staff", "user"].contains(&requested_account_type) {
        return Err(Error::ValidationError(
            "account_type must be 'staff' or 'user'".to_string(),
        ));
    }

    // Hash password and persist hash in DB.
    let password_hash = hash_password(&payload.password)?;

    // Create account in database with stored password hash.
    let repo = SqliteAccountRepository::new(state.db_pool.clone());
    let account = repo
        .create_account(
            &payload.username,
            &payload.email,
            &password_hash,
            requested_account_type,
        )
        .await?;

    let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
    let _ = audit_repo
        .log_event(
            &account.id,
            "account-created",
            &caller.id,
            Some(serde_json::json!({
                "username": payload.username,
                "account_type": requested_account_type,
            })),
        )
        .await?;

    tracing::info!(
        username = %payload.username,
        account_id = %account.id,
        "Account created"
    );

    Ok((StatusCode::CREATED, Json(account.into())))
}

/// Get account by ID
pub async fn get_account(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<String>,
) -> Result<Json<AccountResponse>> {
    // Validate UUID format
    Uuid::parse_str(&account_id)
        .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

    let repo = SqliteAccountRepository::new(state.db_pool.clone());
    let account = repo
        .get_account(&account_id)
        .await?
        .ok_or(Error::NotFound)?;

    Ok(Json(account.into()))
}

/// Update account
pub async fn update_account(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedService>,
    Path(account_id): Path<String>,
    Json(payload): Json<UpdateAccountRequest>,
) -> Result<Json<AccountResponse>> {
    // Validate UUID format
    Uuid::parse_str(&account_id)
        .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

    if let Some(ref email) = payload.email {
        if email.is_empty() || email.len() > 255 {
            return Err(Error::ValidationError("Invalid email".to_string()));
        }
    }

    let repo = SqliteAccountRepository::new(state.db_pool.clone());
    let account = repo
        .update_account(&account_id, payload.email.as_deref(), payload.is_active)
        .await?;

    let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
    let _ = audit_repo
        .log_event(
            &account_id,
            "account-updated",
            &caller.id,
            Some(serde_json::json!({
                "email": payload.email,
                "is_active": payload.is_active,
            })),
        )
        .await?;

    tracing::info!(
        account_id = %account_id,
        email = ?payload.email,
        is_active = ?payload.is_active,
        "Account updated"
    );

    Ok(Json(account.into()))
}

/// Delete (disable) account
pub async fn delete_account(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedService>,
    Path(account_id): Path<String>,
) -> Result<StatusCode> {
    // Validate UUID format
    Uuid::parse_str(&account_id)
        .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

    let repo = SqliteAccountRepository::new(state.db_pool.clone());

    // Soft delete: just disable the account
    repo.update_account(&account_id, None, Some(false)).await?;

    let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
    let _ = audit_repo
        .log_event(
            &account_id,
            "account-disabled",
            &caller.id,
            None,
        )
        .await?;

    tracing::info!(account_id = %account_id, "Account disabled");

    Ok(StatusCode::NO_CONTENT)
}

/// Lookup account by email or username
pub async fn lookup_account(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LookupQuery>,
) -> Result<Json<AccountResponse>> {
    if params.email.is_none() && params.username.is_none() {
        return Err(Error::ValidationError(
            "Either email or username query parameter is required".to_string(),
        ));
    }

    let repo = SqliteAccountRepository::new(state.db_pool.clone());

    let account = if let Some(email) = params.email {
        repo.get_account_by_email(&email)
            .await?
            .ok_or(Error::NotFound)?
    } else if let Some(username) = params.username {
        repo.get_account_by_username(&username)
            .await?
            .ok_or(Error::NotFound)?
    } else {
        return Err(Error::NotFound);
    };

    Ok(Json(account.into()))
}

