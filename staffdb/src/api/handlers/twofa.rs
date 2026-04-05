use axum::{
  extract::{Extension, Path, State},
  http::StatusCode,
  Json,
};
use chrono::Utc;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
  api::middleware::AuthenticatedService,
  auth::{generate_totp_secret_base32, verify_totp_code},
  db::SqliteAuditLogRepository,
  error::{Error, Result},
  models::{EnrollTotpRequest, TotpEnrollResponse, TotpStatusResponse, VerifyTotpRequest},
  AppState,
};
use crate::db::AuditLogRepository;

fn valid_totp_code_format(input: &str) -> bool {
  input.len() == 6 && input.chars().all(|ch| ch.is_ascii_digit())
}

pub async fn enroll_totp(
  State(state): State<Arc<AppState>>,
  Extension(caller): Extension<AuthenticatedService>,
  Path(account_id): Path<String>,
  Json(payload): Json<EnrollTotpRequest>,
) -> Result<(StatusCode, Json<TotpEnrollResponse>)> {
  Uuid::parse_str(&account_id)
    .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

  let account_exists = sqlx::query("SELECT id FROM accounts WHERE id = ?")
    .bind(&account_id)
    .fetch_optional(&state.db_pool)
    .await?
    .is_some();

  if !account_exists {
    return Err(Error::NotFound);
  }

  let secret_base32 = generate_totp_secret_base32();
  let now = Utc::now();

  sqlx::query(
    r#"
      INSERT INTO account_totp_factors (account_id, secret_base32, is_confirmed, created_at, updated_at)
      VALUES (?, ?, false, ?, ?)
      ON CONFLICT(account_id) DO UPDATE SET
        secret_base32 = excluded.secret_base32,
        is_confirmed = false,
        updated_at = excluded.updated_at,
        last_verified_at = NULL
    "#,
  )
  .bind(&account_id)
  .bind(&secret_base32)
  .bind(now)
  .bind(now)
  .execute(&state.db_pool)
  .await?;

  sqlx::query("UPDATE accounts SET two_factor_enabled = false, updated_at = ? WHERE id = ?")
    .bind(now)
    .bind(&account_id)
    .execute(&state.db_pool)
    .await?;

  let issuer = payload.issuer.unwrap_or_else(|| "StellaraeSecure".to_string());
  let otpauth_uri = format!(
    "otpauth://totp/{}:{}?secret={}&issuer={}",
    issuer,
    account_id,
    secret_base32,
    issuer,
  );

  let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
  let _ = audit_repo
    .log_event(
      &account_id,
      "2fa-totp-enrollment-started",
      &caller.id,
      Some(serde_json::json!({
        "method": "totp",
      })),
    )
    .await?;

  Ok((
    StatusCode::CREATED,
    Json(TotpEnrollResponse {
      account_id,
      secret_base32,
      otpauth_uri,
    }),
  ))
}

pub async fn verify_totp(
  State(state): State<Arc<AppState>>,
  Extension(caller): Extension<AuthenticatedService>,
  Path(account_id): Path<String>,
  Json(payload): Json<VerifyTotpRequest>,
) -> Result<(StatusCode, Json<TotpStatusResponse>)> {
  Uuid::parse_str(&account_id)
    .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

  if !valid_totp_code_format(payload.code.trim()) {
    return Err(Error::ValidationError(
      "TOTP code must be exactly 6 digits".to_string(),
    ));
  }

  let row = sqlx::query(
    "SELECT secret_base32 FROM account_totp_factors WHERE account_id = ?",
  )
  .bind(&account_id)
  .fetch_optional(&state.db_pool)
  .await?;

  let Some(row) = row else {
    return Err(Error::ValidationError(
      "No pending TOTP enrollment for account".to_string(),
    ));
  };

  let secret_base32: String = row.get("secret_base32");
  let valid = verify_totp_code(&secret_base32, &payload.code, Utc::now().timestamp())?;
  if !valid {
    return Err(Error::AuthenticationError("Invalid TOTP code".to_string()));
  }

  let now = Utc::now();
  sqlx::query(
    "UPDATE account_totp_factors SET is_confirmed = true, updated_at = ?, last_verified_at = ? WHERE account_id = ?",
  )
  .bind(now)
  .bind(now)
  .bind(&account_id)
  .execute(&state.db_pool)
  .await?;

  sqlx::query("UPDATE accounts SET two_factor_enabled = true, updated_at = ? WHERE id = ?")
    .bind(now)
    .bind(&account_id)
    .execute(&state.db_pool)
    .await?;

  let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
  let _ = audit_repo
    .log_event(
      &account_id,
      "2fa-totp-verified",
      &caller.id,
      Some(serde_json::json!({
        "method": "totp",
      })),
    )
    .await?;

  Ok((
    StatusCode::OK,
    Json(TotpStatusResponse {
      account_id,
      two_factor_enabled: true,
      method: Some("totp".to_string()),
    }),
  ))
}

pub async fn get_2fa_status(
  State(state): State<Arc<AppState>>,
  Path(account_id): Path<String>,
) -> Result<Json<TotpStatusResponse>> {
  Uuid::parse_str(&account_id)
    .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

  let row = sqlx::query("SELECT two_factor_enabled FROM accounts WHERE id = ?")
    .bind(&account_id)
    .fetch_optional(&state.db_pool)
    .await?;

  let Some(row) = row else {
    return Err(Error::NotFound);
  };

  let enabled: bool = row.get("two_factor_enabled");
  Ok(Json(TotpStatusResponse {
    account_id,
    two_factor_enabled: enabled,
    method: if enabled { Some("totp".to_string()) } else { None },
  }))
}
