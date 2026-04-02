// Audit log endpoints (Phase 4)

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    db::{AuditLogRepository, SqliteAuditLogRepository},
    error::{Error, Result},
    AppState,
};

/// Audit event response
#[derive(Serialize)]
pub struct AuditEventResponse {
    pub id: String,
    pub account_id: String,
    pub action: String,
    pub actor_service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub timestamp: String,
}

/// Pagination parameters
#[derive(Deserialize)]
pub struct PaginationParams {
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// Audit log list response
#[derive(Serialize)]
pub struct AuditLogResponse {
    pub account_id: String,
    pub events: Vec<AuditEventResponse>,
    pub total: i64,
    pub limit: i32,
    pub offset: i32,
}

/// Get audit log for an account
pub async fn get_audit_log(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<AuditLogResponse>> {
    // Validate account ID format
    Uuid::parse_str(&account_id)
        .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

    let limit = params.limit.unwrap_or(50).max(1).min(1000);
    let offset = params.offset.unwrap_or(0).max(0);

    let repo = SqliteAuditLogRepository::new(state.db_pool.clone());

    let events = repo.get_events(&account_id, limit, offset).await?;
    let total = repo.count_events(&account_id).await?;

    let response = AuditLogResponse {
        account_id,
        events: events
            .into_iter()
            .map(|e| AuditEventResponse {
                id: e.id,
                account_id: e.account_id,
                action: e.action,
                actor_service: e.actor_service,
                details: e.details,
                timestamp: e.timestamp.to_rfc3339(),
            })
            .collect(),
        total,
        limit,
        offset,
    };

    Ok(Json(response))
}
