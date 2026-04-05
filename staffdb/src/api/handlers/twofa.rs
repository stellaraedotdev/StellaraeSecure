use axum::{
  extract::{Extension, Path, State},
  http::StatusCode,
  Json,
};
use chrono::{Duration, Utc};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
  api::middleware::AuthenticatedService,
  auth::{
    generate_totp_secret_base32,
    verify_hsk_assertion,
    verify_totp_code,
  },
  db::SqliteAuditLogRepository,
  error::{Error, Result},
  models::{
    EnrollHskChallengeRequest,
    EnrollTotpRequest,
    HskChallengeResponse,
    TotpEnrollResponse,
    TotpStatusResponse,
    VerifyHskRequest,
    VerifyTotpRequest,
  },
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

  let status_row = sqlx::query("SELECT hsk_enabled FROM accounts WHERE id = ?")
    .bind(&account_id)
    .fetch_one(&state.db_pool)
    .await?;
  let hsk_enabled: bool = status_row.get("hsk_enabled");

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
      hsk_enabled,
      method: if hsk_enabled {
        Some("totp+hsk".to_string())
      } else {
        Some("totp".to_string())
      },
    }),
  ))
}

pub async fn get_2fa_status(
  State(state): State<Arc<AppState>>,
  Path(account_id): Path<String>,
) -> Result<Json<TotpStatusResponse>> {
  Uuid::parse_str(&account_id)
    .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

  let row = sqlx::query("SELECT two_factor_enabled, hsk_enabled FROM accounts WHERE id = ?")
    .bind(&account_id)
    .fetch_optional(&state.db_pool)
    .await?;

  let Some(row) = row else {
    return Err(Error::NotFound);
  };

  let totp_enabled: bool = row.get("two_factor_enabled");
  let hsk_enabled: bool = row.get("hsk_enabled");
  let method = match (totp_enabled, hsk_enabled) {
    (true, true) => Some("totp+hsk".to_string()),
    (true, false) => Some("totp".to_string()),
    (false, true) => Some("hsk".to_string()),
    (false, false) => None,
  };

  Ok(Json(TotpStatusResponse {
    account_id,
    two_factor_enabled: totp_enabled,
    hsk_enabled,
    method,
  }))
}

fn valid_hsk_credential_id(input: &str) -> bool {
  !input.trim().is_empty() && input.trim().len() <= 255
}

pub async fn start_hsk_challenge(
  State(state): State<Arc<AppState>>,
  Extension(caller): Extension<AuthenticatedService>,
  Path(account_id): Path<String>,
  Json(payload): Json<EnrollHskChallengeRequest>,
) -> Result<(StatusCode, Json<HskChallengeResponse>)> {
  Uuid::parse_str(&account_id)
    .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

  if !valid_hsk_credential_id(&payload.credential_id) {
    return Err(Error::ValidationError(
      "credential_id must be 1-255 characters".to_string(),
    ));
  }

  let account_exists = sqlx::query("SELECT id FROM accounts WHERE id = ?")
    .bind(&account_id)
    .fetch_optional(&state.db_pool)
    .await?
    .is_some();

  if !account_exists {
    return Err(Error::NotFound);
  }

  let challenge = Uuid::new_v4().to_string();
  let now = Utc::now();
  let challenge_expires_at = now + Duration::minutes(5);

  sqlx::query(
    r#"
      INSERT INTO account_hsk_factors (
        account_id,
        credential_id,
        label,
        challenge,
        challenge_expires_at,
        is_confirmed,
        created_at,
        updated_at,
        last_verified_at
      )
      VALUES (?, ?, ?, ?, ?, false, ?, ?, NULL)
      ON CONFLICT(account_id, credential_id) DO UPDATE SET
        label = excluded.label,
        challenge = excluded.challenge,
        challenge_expires_at = excluded.challenge_expires_at,
        updated_at = excluded.updated_at,
        last_verified_at = NULL
    "#,
  )
  .bind(&account_id)
  .bind(payload.credential_id.trim())
  .bind(payload.label.as_deref())
  .bind(&challenge)
  .bind(challenge_expires_at)
  .bind(now)
  .bind(now)
  .execute(&state.db_pool)
  .await?;

  let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
  let _ = audit_repo
    .log_event(
      &account_id,
      "2fa-hsk-challenge-started",
      &caller.id,
      Some(serde_json::json!({
        "method": "hsk",
        "credential_id": payload.credential_id.trim(),
      })),
    )
    .await?;

  Ok((
    StatusCode::CREATED,
    Json(HskChallengeResponse {
      account_id,
      credential_id: payload.credential_id.trim().to_string(),
      challenge,
      expires_at: challenge_expires_at.to_rfc3339(),
    }),
  ))
}

pub async fn verify_hsk_challenge(
  State(state): State<Arc<AppState>>,
  Extension(caller): Extension<AuthenticatedService>,
  Path(account_id): Path<String>,
  Json(payload): Json<VerifyHskRequest>,
) -> Result<(StatusCode, Json<TotpStatusResponse>)> {
  Uuid::parse_str(&account_id)
    .map_err(|_| Error::ValidationError("Invalid account ID format".to_string()))?;

  if !valid_hsk_credential_id(&payload.credential_id) {
    return Err(Error::ValidationError(
      "credential_id must be 1-255 characters".to_string(),
    ));
  }

  if payload.challenge.trim().is_empty() {
    return Err(Error::ValidationError("challenge is required".to_string()));
  }

  if payload.assertion.trim().is_empty() {
    return Err(Error::ValidationError("assertion is required".to_string()));
  }

  let row = sqlx::query(
    r#"
      SELECT challenge, challenge_expires_at
      FROM account_hsk_factors
      WHERE account_id = ? AND credential_id = ?
    "#,
  )
  .bind(&account_id)
  .bind(payload.credential_id.trim())
  .fetch_optional(&state.db_pool)
  .await?;

  let Some(row) = row else {
    return Err(Error::ValidationError(
      "No pending HSK challenge for credential".to_string(),
    ));
  };

  let stored_challenge: Option<String> = row.get("challenge");
  let Some(stored_challenge) = stored_challenge else {
    return Err(Error::ValidationError(
      "No active HSK challenge found".to_string(),
    ));
  };

  if stored_challenge != payload.challenge.trim() {
    return Err(Error::AuthenticationError("Invalid HSK challenge".to_string()));
  }

  let challenge_expires_at: Option<chrono::DateTime<Utc>> = row.get("challenge_expires_at");
  if let Some(expires_at) = challenge_expires_at {
    if Utc::now() > expires_at {
      return Err(Error::AuthenticationError("HSK challenge expired".to_string()));
    }
  }

  if !verify_hsk_assertion(
    payload.challenge.trim(),
    payload.credential_id.trim(),
    payload.assertion.trim(),
  ) {
    return Err(Error::AuthenticationError(
      "Invalid HSK assertion".to_string(),
    ));
  }

  let now = Utc::now();
  sqlx::query(
    r#"
      UPDATE account_hsk_factors
      SET is_confirmed = true,
          challenge = NULL,
          challenge_expires_at = NULL,
          updated_at = ?,
          last_verified_at = ?
      WHERE account_id = ? AND credential_id = ?
    "#,
  )
  .bind(now)
  .bind(now)
  .bind(&account_id)
  .bind(payload.credential_id.trim())
  .execute(&state.db_pool)
  .await?;

  sqlx::query("UPDATE accounts SET hsk_enabled = true, updated_at = ? WHERE id = ?")
    .bind(now)
    .bind(&account_id)
    .execute(&state.db_pool)
    .await?;

  let audit_repo = SqliteAuditLogRepository::new(state.db_pool.clone());
  let _ = audit_repo
    .log_event(
      &account_id,
      "2fa-hsk-verified",
      &caller.id,
      Some(serde_json::json!({
        "method": "hsk",
        "credential_id": payload.credential_id.trim(),
      })),
    )
    .await?;

  let status_row = sqlx::query("SELECT two_factor_enabled, hsk_enabled FROM accounts WHERE id = ?")
    .bind(&account_id)
    .fetch_one(&state.db_pool)
    .await?;
  let totp_enabled: bool = status_row.get("two_factor_enabled");
  let hsk_enabled: bool = status_row.get("hsk_enabled");
  let method = match (totp_enabled, hsk_enabled) {
    (true, true) => Some("totp+hsk".to_string()),
    (true, false) => Some("totp".to_string()),
    (false, true) => Some("hsk".to_string()),
    (false, false) => None,
  };

  Ok((
    StatusCode::OK,
    Json(TotpStatusResponse {
      account_id,
      two_factor_enabled: totp_enabled,
      hsk_enabled,
      method,
    }),
  ))
}
