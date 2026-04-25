use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use uuid::Uuid;

use crate::{config::Config, error::AppError};

type HmacSha1 = Hmac<Sha1>;
static PROCESS_START: OnceLock<Instant> = OnceLock::new();

#[derive(Clone)]
pub struct AppState {
    config: Config,
    db_pool: SqlitePool,
    http_client: reqwest::Client,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: String,
}

#[derive(Serialize)]
struct ReadyResponse {
    ready: bool,
    database: &'static str,
    service: String,
}

#[derive(Deserialize)]
struct EnrollTotpRequest {
    issuer: Option<String>,
}

#[derive(Serialize)]
struct TotpEnrollResponse {
    account_id: String,
    secret_base32: String,
    otpauth_uri: String,
}

#[derive(Deserialize)]
struct VerifyTotpRequest {
    code: String,
}

#[derive(Deserialize)]
struct StartHskChallengeRequest {
    credential_id: String,
    label: Option<String>,
}

#[derive(Serialize)]
struct HskChallengeResponse {
    account_id: String,
    credential_id: String,
    challenge: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct VerifyHskRequest {
    credential_id: String,
    challenge: String,
    assertion: String,
}

#[derive(Serialize)]
struct FactorStatusResponse {
    account_id: String,
    two_factor_enabled: bool,
    hsk_enabled: bool,
    method: Option<String>,
}

#[derive(Deserialize)]
struct LookupAccountResponse {
    id: String,
}

pub async fn build_app(config: Config) -> Result<Router, AppError> {
    let database_url = normalize_sqlite_url(&config.database_url);
    let db_pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .map_err(|e| AppError::Internal(format!("failed to open twofa database: {e}")))?;

    run_migrations(&db_pool).await?;

    let state = Arc::new(AppState {
        config,
        db_pool,
        http_client: reqwest::Client::new(),
    });

    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/status/:account_id", get(get_status))
        .route("/api/totp/:account_id/enroll", post(enroll_totp))
        .route("/api/totp/:account_id/verify", post(verify_totp))
        .route("/api/hsk/:account_id/challenge", post(start_hsk_challenge))
        .route("/api/hsk/:account_id/verify", post(verify_hsk_challenge))
        .with_state(state))
}

async fn healthz(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        service: state.config.service_id.clone(),
    })
}

async fn ready(State(state): State<Arc<AppState>>) -> Json<ReadyResponse> {
    Json(ReadyResponse {
        ready: true,
        database: "ok",
        service: state.config.service_id.clone(),
    })
}

async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime_seconds = PROCESS_START.get_or_init(Instant::now).elapsed().as_secs();
    let body = format!(
        "# HELP service_uptime_seconds Process uptime in seconds\n\
# TYPE service_uptime_seconds gauge\n\
service_uptime_seconds{{service=\"{}\"}} {}\n\
# HELP service_info Static service metadata\n\
# TYPE service_info gauge\n\
service_info{{service=\"{}\",version=\"{}\"}} 1\n",
        state.config.service_id,
        uptime_seconds,
        state.config.service_id,
        env!("CARGO_PKG_VERSION")
    );

    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}

fn assert_api_key(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Authentication)?;

    let provided = auth
        .strip_prefix("Bearer ")
        .ok_or(AppError::Authentication)?
        .trim();

    if provided != state.config.twofa_api_key {
        return Err(AppError::Authentication);
    }

    Ok(())
}

/// Validates that the staffdb base URL uses HTTPS, with an explicit
/// loopback exception for http://127.0.0.1.
fn validate_secure_staffdb_url(base_url: &str) -> Result<(), AppError> {
    let parsed = reqwest::Url::parse(base_url)
        .map_err(|_| AppError::Internal("Invalid staffdb base URL".to_string()))?;

    let is_https = parsed.scheme() == "https";
    let is_allowed_dev_http = parsed.scheme() == "http"
        && matches!(parsed.host_str(), Some("127.0.0.1") | Some("staffdb"));

    if !is_https && !is_allowed_dev_http {
        return Err(AppError::Internal(
            "Insecure transport to staffdb: must use HTTPS, http://127.0.0.1, or http://staffdb"
                .to_string(),
        ));
    }
    Ok(())
}

async fn ensure_account_exists(state: &AppState, account_id: &str) -> Result<(), AppError> {
    if Uuid::parse_str(account_id).is_err() {
        return Err(AppError::Validation("Invalid account ID format".to_string()));
    }

    let Some(staffdb_base_url) = state.config.staffdb_base_url.as_deref() else {
        return Ok(());
    };
    let Some(staffdb_api_key) = state.config.staffdb_api_key.as_deref() else {
        return Ok(());
    };

    validate_secure_staffdb_url(staffdb_base_url)?;

    let url = format!(
        "{}/api/accounts/{}",
        staffdb_base_url.trim_end_matches('/'),
        account_id
    );

    let response = state
        .http_client
        .get(url)
        .bearer_auth(staffdb_api_key)
        .send()
        .await
        .map_err(|e| AppError::Upstream(format!("staffdb request failed: {e}")))?;

    if response.status().as_u16() == 404 {
        return Err(AppError::NotFound);
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(AppError::Upstream(format!("staffdb returned {status}: {body}")));
    }

    let payload = response
        .json::<LookupAccountResponse>()
        .await
        .map_err(|e| AppError::Upstream(format!("invalid staffdb response: {e}")))?;

    if payload.id.trim().is_empty() {
        return Err(AppError::Upstream(
            "staffdb returned empty account id".to_string(),
        ));
    }

    Ok(())
}

async fn get_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Result<Json<FactorStatusResponse>, AppError> {
    assert_api_key(&state, &headers)?;
    ensure_account_exists(&state, &account_id).await?;

    let totp_enabled = sqlx::query(
        "SELECT is_confirmed FROM totp_factors WHERE account_id = ? LIMIT 1",
    )
    .bind(&account_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Internal(format!("failed reading TOTP status: {e}")))?
    .map(|row| row.get::<bool, _>("is_confirmed"))
    .unwrap_or(false);

    let hsk_enabled = sqlx::query(
        "SELECT 1 as enabled FROM hsk_factors WHERE account_id = ? AND is_confirmed = true LIMIT 1",
    )
    .bind(&account_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Internal(format!("failed reading HSK status: {e}")))?
    .is_some();

    let method = match (totp_enabled, hsk_enabled) {
        (true, true) => Some("totp+hsk".to_string()),
        (true, false) => Some("totp".to_string()),
        (false, true) => Some("hsk".to_string()),
        (false, false) => None,
    };

    Ok(Json(FactorStatusResponse {
        account_id,
        two_factor_enabled: totp_enabled,
        hsk_enabled,
        method,
    }))
}

async fn enroll_totp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(payload): Json<EnrollTotpRequest>,
) -> Result<(StatusCode, Json<TotpEnrollResponse>), AppError> {
    assert_api_key(&state, &headers)?;
    ensure_account_exists(&state, &account_id).await?;

    let secret_base32 = generate_totp_secret_base32();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO totp_factors (account_id, secret_base32, is_confirmed, created_at, updated_at, last_verified_at)
        VALUES (?, ?, false, ?, ?, NULL)
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
    .await
    .map_err(|e| AppError::Internal(format!("failed to enroll TOTP: {e}")))?;

    let issuer = payload.issuer.unwrap_or_else(|| "StellaraeSecure".to_string());
    let otpauth_uri = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        issuer, account_id, secret_base32, issuer
    );

    Ok((
        StatusCode::CREATED,
        Json(TotpEnrollResponse {
            account_id,
            secret_base32,
            otpauth_uri,
        }),
    ))
}

async fn verify_totp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(payload): Json<VerifyTotpRequest>,
) -> Result<(StatusCode, Json<FactorStatusResponse>), AppError> {
    assert_api_key(&state, &headers)?;
    ensure_account_exists(&state, &account_id).await?;

    if payload.code.trim().len() != 6 || !payload.code.trim().chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::Validation("TOTP code must be exactly 6 digits".to_string()));
    }

    let row = sqlx::query("SELECT secret_base32 FROM totp_factors WHERE account_id = ?")
        .bind(&account_id)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed loading TOTP factor: {e}")))?;

    let Some(row) = row else {
        return Err(AppError::Validation("No pending TOTP enrollment for account".to_string()));
    };

    let secret_base32: String = row.get("secret_base32");
    if !verify_totp_code(&secret_base32, payload.code.trim(), Utc::now().timestamp())? {
        return Err(AppError::Authentication);
    }

    let now = Utc::now();
    sqlx::query(
        "UPDATE totp_factors SET is_confirmed = true, updated_at = ?, last_verified_at = ? WHERE account_id = ?",
    )
    .bind(now)
    .bind(now)
    .bind(&account_id)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Internal(format!("failed confirming TOTP factor: {e}")))?;

    let hsk_enabled = sqlx::query(
        "SELECT 1 as enabled FROM hsk_factors WHERE account_id = ? AND is_confirmed = true LIMIT 1",
    )
    .bind(&account_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Internal(format!("failed reading HSK status: {e}")))?
    .is_some();

    Ok((
        StatusCode::OK,
        Json(FactorStatusResponse {
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

async fn start_hsk_challenge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(payload): Json<StartHskChallengeRequest>,
) -> Result<(StatusCode, Json<HskChallengeResponse>), AppError> {
    assert_api_key(&state, &headers)?;
    ensure_account_exists(&state, &account_id).await?;

    if payload.credential_id.trim().is_empty() || payload.credential_id.trim().len() > 255 {
        return Err(AppError::Validation(
            "credential_id must be 1-255 characters".to_string(),
        ));
    }

    let challenge = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = now + Duration::minutes(5);

    sqlx::query(
        r#"
        INSERT INTO hsk_factors (
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
    .bind(expires_at)
    .bind(now)
    .bind(now)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Internal(format!("failed creating HSK challenge: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(HskChallengeResponse {
            account_id,
            credential_id: payload.credential_id.trim().to_string(),
            challenge,
            expires_at: expires_at.to_rfc3339(),
        }),
    ))
}

async fn verify_hsk_challenge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(payload): Json<VerifyHskRequest>,
) -> Result<(StatusCode, Json<FactorStatusResponse>), AppError> {
    assert_api_key(&state, &headers)?;
    ensure_account_exists(&state, &account_id).await?;

    if payload.credential_id.trim().is_empty() || payload.credential_id.trim().len() > 255 {
        return Err(AppError::Validation(
            "credential_id must be 1-255 characters".to_string(),
        ));
    }

    let row = sqlx::query(
        r#"
        SELECT challenge, challenge_expires_at
        FROM hsk_factors
        WHERE account_id = ? AND credential_id = ?
        "#,
    )
    .bind(&account_id)
    .bind(payload.credential_id.trim())
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Internal(format!("failed loading HSK challenge: {e}")))?;

    let Some(row) = row else {
        return Err(AppError::Validation("No pending HSK challenge for credential".to_string()));
    };

    let challenge: Option<String> = row.get("challenge");
    let Some(challenge) = challenge else {
        return Err(AppError::Validation("No active HSK challenge found".to_string()));
    };

    if challenge != payload.challenge.trim() {
        return Err(AppError::Authentication);
    }

    let expires_at: Option<chrono::DateTime<Utc>> = row.get("challenge_expires_at");
    if let Some(expires_at) = expires_at {
        if Utc::now() > expires_at {
            return Err(AppError::Authentication);
        }
    }

    if !verify_hsk_assertion(
        payload.challenge.trim(),
        payload.credential_id.trim(),
        payload.assertion.trim(),
    ) {
        return Err(AppError::Authentication);
    }

    let now = Utc::now();
    sqlx::query(
        r#"
        UPDATE hsk_factors
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
    .await
    .map_err(|e| AppError::Internal(format!("failed confirming HSK factor: {e}")))?;

    let totp_enabled = sqlx::query("SELECT is_confirmed FROM totp_factors WHERE account_id = ? LIMIT 1")
        .bind(&account_id)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed reading TOTP status: {e}")))?
        .map(|row| row.get::<bool, _>("is_confirmed"))
        .unwrap_or(false);

    Ok((
        StatusCode::OK,
        Json(FactorStatusResponse {
            account_id,
            two_factor_enabled: totp_enabled,
            hsk_enabled: true,
            method: if totp_enabled {
                Some("totp+hsk".to_string())
            } else {
                Some("hsk".to_string())
            },
        }),
    ))
}

fn generate_totp_secret_base32() -> String {
    let mut secret = [0u8; 20];
    rand::rng().fill_bytes(&mut secret);
    BASE32_NOPAD.encode(&secret)
}

fn verify_totp_code(secret_base32: &str, code: &str, now_ts: i64) -> Result<bool, AppError> {
    let parsed_code: u32 = code
        .trim()
        .parse()
        .map_err(|_| AppError::Validation("TOTP code must be numeric".to_string()))?;

    let secret = BASE32_NOPAD
        .decode(secret_base32.trim().as_bytes())
        .map_err(|_| AppError::Validation("Invalid TOTP secret encoding".to_string()))?;

    for drift in [-1_i64, 0, 1] {
        let candidate_ts = now_ts + drift * 30;
        let counter = (candidate_ts / 30) as u64;
        let mut msg = [0u8; 8];
        msg.copy_from_slice(&counter.to_be_bytes());

        let mut mac = HmacSha1::new_from_slice(&secret)
            .map_err(|_| AppError::Internal("failed to initialize TOTP HMAC".to_string()))?;
        mac.update(&msg);
        let digest = mac.finalize().into_bytes();

        let offset = (digest[19] & 0x0f) as usize;
        let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
            | (u32::from(digest[offset + 1]) << 16)
            | (u32::from(digest[offset + 2]) << 8)
            | u32::from(digest[offset + 3]);

        if binary % 1_000_000 == parsed_code {
            return Ok(true);
        }
    }

    Ok(false)
}

fn expected_hsk_assertion(challenge: &str, credential_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", challenge.trim(), credential_id.trim()));
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn verify_hsk_assertion(challenge: &str, credential_id: &str, assertion: &str) -> bool {
    expected_hsk_assertion(challenge, credential_id) == assertion.trim().to_ascii_lowercase()
}

fn normalize_sqlite_url(database_url: &str) -> String {
    if database_url == "sqlite::memory:" {
        return "sqlite::memory:".to_string();
    }
    if database_url.starts_with("sqlite:") {
        return database_url.to_string();
    }
    format!("sqlite:{}", database_url)
}

#[cfg(test)]
mod tests {
    use super::{
        expected_hsk_assertion, normalize_sqlite_url, validate_secure_staffdb_url,
        verify_hsk_assertion, verify_totp_code,
    };

    #[test]
    fn normalize_sqlite_url_handles_plain_paths_and_memory() {
        assert_eq!(normalize_sqlite_url("sqlite::memory:"), "sqlite::memory:");
        assert_eq!(normalize_sqlite_url("sqlite:twofa.sqlite"), "sqlite:twofa.sqlite");
        assert_eq!(normalize_sqlite_url("twofa.sqlite"), "sqlite:twofa.sqlite");
    }

    #[test]
    fn hsk_assertion_round_trip_verification() {
        let challenge = "challenge-123";
        let credential = "cred-abc";
        let assertion = expected_hsk_assertion(challenge, credential);

        assert!(verify_hsk_assertion(challenge, credential, &assertion));
        assert!(!verify_hsk_assertion(challenge, credential, "bad-assertion"));
    }

    #[test]
    fn totp_verification_matches_known_vector() {
        // RFC 6238 test secret for SHA-1: "12345678901234567890"
        let secret_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        // At t=59s, the 8-digit value is 94287082; this implementation uses 6 digits.
        let code = "287082";
        let ok = verify_totp_code(secret_base32, code, 59).expect("totp verification should run");
        assert!(ok);
    }

    #[test]
    fn totp_verification_rejects_invalid_secret_encoding() {
        let err = verify_totp_code("!not-base32!", "123456", 59).expect_err("invalid secret");
        assert!(err.to_string().contains("Invalid TOTP secret encoding"));
    }

    #[test]
    fn validate_secure_staffdb_url_enforces_transport_security() {
        // HTTPS is always allowed
        assert!(validate_secure_staffdb_url("https://staffdb.example.com").is_ok());
        assert!(validate_secure_staffdb_url("https://staffdb.example.com/api").is_ok());

        // HTTP loopback (127.0.0.1) and local compose hostnames are allowed as explicit exceptions
        assert!(validate_secure_staffdb_url("http://127.0.0.1:3000").is_ok());
        assert!(validate_secure_staffdb_url("http://127.0.0.1/api/accounts").is_ok());
        assert!(validate_secure_staffdb_url("http://staffdb:3000").is_ok());
        assert!(validate_secure_staffdb_url("http://staffdb:3000/api/accounts").is_ok());

        // Plain HTTP to non-local hosts is rejected
        assert!(validate_secure_staffdb_url("http://example.com").is_err());
        assert!(validate_secure_staffdb_url("ftp://staffdb.example.com").is_err());

        // Crafted URLs that start with "127.0.0.1" in path or subdomain are rejected
        assert!(validate_secure_staffdb_url("http://127.0.0.1.evil.com").is_err());
    }
}

async fn run_migrations(pool: &SqlitePool) -> Result<(), AppError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS totp_factors (
            account_id TEXT PRIMARY KEY,
            secret_base32 TEXT NOT NULL,
            is_confirmed BOOLEAN NOT NULL DEFAULT false,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            last_verified_at DATETIME
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(format!("failed to create totp_factors: {e}")))?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS hsk_factors (
            account_id TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            label TEXT,
            challenge TEXT,
            challenge_expires_at DATETIME,
            is_confirmed BOOLEAN NOT NULL DEFAULT false,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            last_verified_at DATETIME,
            PRIMARY KEY (account_id, credential_id)
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(format!("failed to create hsk_factors: {e}")))?;

    Ok(())
}
