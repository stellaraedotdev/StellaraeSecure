use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use rand::{distr::Alphanumeric, rng, Rng};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use serde::{de::DeserializeOwned, Serialize};

use crate::config::Config;
use crate::db::migrations::run_migrations;
use crate::error::AppError;
use crate::models::{
    AccessToken,
    AdminAuditEvent,
    AuthorizationCode,
    OAuthClient,
    PanelSession,
    PendingConsent,
    RefreshToken,
};

#[derive(Default)]
pub struct MemoryStore {
    pub clients: HashMap<String, OAuthClient>,
    pub pending_consents: HashMap<String, PendingConsent>,
    pub auth_codes: HashMap<String, AuthorizationCode>,
    pub access_tokens: HashMap<String, AccessToken>,
    pub refresh_tokens: HashMap<String, RefreshToken>,
    pub panel_sessions: HashMap<String, PanelSession>,
    pub admin_audit_events: Vec<AdminAuditEvent>,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub staffdb_base_url: reqwest::Url,
    pub store: Arc<Mutex<MemoryStore>>,
    pub db: Arc<Mutex<Connection>>,
    pub http_client: reqwest::Client,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, AppError> {
        crate::staffdb::validate_secure_url(&config.staffdb_base_url, &config.environment)?;
        let staffdb_base_url = reqwest::Url::parse(&config.staffdb_base_url)
            .map_err(|_| AppError::Config("STAFFDB_BASE_URL is not a valid URL".to_string()))?;

        let database_url = normalize_sqlite_url(&config.database_url);
        let connection = Connection::open(database_url)
            .map_err(|error| AppError::Config(format!("failed to open oauth2 database: {error}")))?;
        run_migrations(&connection)?;

        Ok(Self {
            config,
            staffdb_base_url,
            store: Arc::new(Mutex::new(MemoryStore::default())),
            db: Arc::new(Mutex::new(connection)),
            http_client: reqwest::Client::new(),
        })
    }

    pub fn persist_oauth_client(&self, client: &OAuthClient) -> Result<(), AppError> {
        persist_json_row(&self.db, "oauth_clients", "id", &client.client_id, client)
    }

    pub fn load_oauth_client(&self, client_id: &str) -> Result<Option<OAuthClient>, AppError> {
        load_json_row(&self.db, "oauth_clients", "id", client_id)
    }

    pub fn delete_oauth_client(&self, client_id: &str) -> Result<(), AppError> {
        let connection = self
            .db
            .lock()
            .map_err(|_| AppError::Internal("database lock poisoned".to_string()))?;

        connection
            .execute("DELETE FROM oauth_clients WHERE id = ?1", params![client_id])
            .map_err(|error| AppError::Internal(format!("failed to delete oauth client: {error}")))?;

        Ok(())
    }

    pub fn persist_pending_consent(&self, consent: &PendingConsent) -> Result<(), AppError> {
        persist_json_row(&self.db, "pending_consents", "request_id", &consent.request_id, consent)
    }

    pub fn take_pending_consent(&self, request_id: &str) -> Result<Option<PendingConsent>, AppError> {
        take_json_row(&self.db, "pending_consents", "request_id", request_id)
    }

    pub fn persist_auth_code(&self, auth_code: &AuthorizationCode) -> Result<(), AppError> {
        persist_json_row(&self.db, "authorization_codes", "code", &auth_code.code, auth_code)
    }

    pub fn take_auth_code(&self, code: &str) -> Result<Option<AuthorizationCode>, AppError> {
        take_json_row(&self.db, "authorization_codes", "code", code)
    }

    pub fn persist_access_token(&self, token: &AccessToken) -> Result<(), AppError> {
        persist_json_row(&self.db, "access_tokens", "token", &token.token, token)
    }

    pub fn load_access_token(&self, token: &str) -> Result<Option<AccessToken>, AppError> {
        load_json_row(&self.db, "access_tokens", "token", token)
    }

    pub fn persist_refresh_token(&self, token: &RefreshToken) -> Result<(), AppError> {
        persist_json_row(&self.db, "refresh_tokens", "token", &token.token, token)
    }

    pub fn load_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>, AppError> {
        load_json_row(&self.db, "refresh_tokens", "token", token)
    }

    pub fn save_refresh_token(&self, token: &RefreshToken) -> Result<(), AppError> {
        self.persist_refresh_token(token)
    }

    pub fn persist_admin_audit_event(&self, event: &AdminAuditEvent) -> Result<(), AppError> {
        let connection = self
            .db
            .lock()
            .map_err(|_| AppError::Internal("database lock poisoned".to_string()))?;

        connection
            .execute(
                r#"
                INSERT INTO admin_audit_events (
                    id, actor_account_id, operation, target_type, target_id,
                    decision, correlation_id, timestamp
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    event.id,
                    event.actor_account_id,
                    event.operation,
                    event.target_type,
                    event.target_id,
                    event.decision,
                    event.correlation_id,
                    event.timestamp.to_rfc3339(),
                ],
            )
            .map_err(|error| AppError::Internal(format!("failed to persist audit event: {error}")))?;

        Ok(())
    }

    pub fn load_admin_audit_events(&self) -> Result<Vec<AdminAuditEvent>, AppError> {
        let connection = self
            .db
            .lock()
            .map_err(|_| AppError::Internal("database lock poisoned".to_string()))?;

        let mut statement = connection
            .prepare(
                r#"
                SELECT id, actor_account_id, operation, target_type, target_id,
                       decision, correlation_id, timestamp
                FROM admin_audit_events
                ORDER BY timestamp ASC, id ASC
                "#,
            )
            .map_err(|error| AppError::Internal(format!("failed to read audit events: {error}")))?;

        let rows = statement
            .query_map([], |row| {
                let timestamp_raw: String = row.get(7)?;
                let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_raw)
                    .map(|value| value.with_timezone(&Utc))
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;

                Ok(AdminAuditEvent {
                    id: row.get(0)?,
                    actor_account_id: row.get(1)?,
                    operation: row.get(2)?,
                    target_type: row.get(3)?,
                    target_id: row.get(4)?,
                    decision: row.get(5)?,
                    correlation_id: row.get(6)?,
                    timestamp,
                })
            })
            .map_err(|error| AppError::Internal(format!("failed to query audit events: {error}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| AppError::Internal(format!("failed to load audit events: {error}")))
    }

    pub fn persist_panel_session(&self, session: &PanelSession) -> Result<(), AppError> {
        let connection = self
            .db
            .lock()
            .map_err(|_| AppError::Internal("database lock poisoned".to_string()))?;

        connection
            .execute(
                r#"
                INSERT INTO panel_sessions (
                    id, account_id, permissions_json, issued_at, expires_at
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(id) DO UPDATE SET
                    account_id = excluded.account_id,
                    permissions_json = excluded.permissions_json,
                    issued_at = excluded.issued_at,
                    expires_at = excluded.expires_at
                "#,
                params![
                    session.id,
                    session.account_id,
                    serde_json::to_string(&session.permissions)
                        .map_err(|error| AppError::Internal(format!("failed to serialize permissions: {error}")))?,
                    session.issued_at.to_rfc3339(),
                    session.expires_at.to_rfc3339(),
                ],
            )
            .map_err(|error| AppError::Internal(format!("failed to persist panel session: {error}")))?;

        Ok(())
    }

    pub fn load_panel_session(&self, session_id: &str) -> Result<Option<PanelSession>, AppError> {
        let connection = self
            .db
            .lock()
            .map_err(|_| AppError::Internal("database lock poisoned".to_string()))?;

        let mut statement = connection
            .prepare(
                r#"
                SELECT id, account_id, permissions_json, issued_at, expires_at
                FROM panel_sessions
                WHERE id = ?1
                "#,
            )
            .map_err(|error| AppError::Internal(format!("failed to prepare panel session lookup: {error}")))?;

        let row = statement
            .query_row([session_id], |row| {
                let permissions_raw: String = row.get(2)?;
                let issued_at_raw: String = row.get(3)?;
                let expires_at_raw: String = row.get(4)?;

                let permissions: Vec<String> = serde_json::from_str(&permissions_raw).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;

                let issued_at = chrono::DateTime::parse_from_rfc3339(&issued_at_raw)
                    .map(|value| value.with_timezone(&Utc))
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;

                let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_raw)
                    .map(|value| value.with_timezone(&Utc))
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;

                Ok(PanelSession {
                    id: row.get(0)?,
                    account_id: row.get(1)?,
                    permissions,
                    issued_at,
                    expires_at,
                })
            })
            .optional()
            .map_err(|error| AppError::Internal(format!("failed to query panel session: {error}")))?;

        Ok(row)
    }
}

fn normalize_sqlite_url(database_url: &str) -> String {
    if database_url == "sqlite::memory:" {
        return ":memory:".to_string();
    }

    if let Some(path) = database_url.strip_prefix("sqlite:///") {
        return path.to_string();
    }

    if let Some(path) = database_url.strip_prefix("sqlite://") {
        return path.to_string();
    }

    if let Some(path) = database_url.strip_prefix("sqlite:") {
        return path.to_string();
    }

    database_url.to_string()
}

fn persist_json_row<T: Serialize>(
    db: &Arc<Mutex<Connection>>,
    table: &str,
    key_column: &str,
    key_value: &str,
    value: &T,
) -> Result<(), AppError> {
    validate_sql_identifier(table)?;
    validate_sql_identifier(key_column)?;

    let connection = db
        .lock()
        .map_err(|_| AppError::Internal("database lock poisoned".to_string()))?;
    let payload = serde_json::to_string(value)
        .map_err(|error| AppError::Internal(format!("failed to serialize record: {error}")))?;

    let statement = format!(
        "INSERT INTO {table} ({key_column}, payload_json) VALUES (?1, ?2) ON CONFLICT({key_column}) DO UPDATE SET payload_json = excluded.payload_json"
    );

    connection
        .execute(&statement, params![key_value, payload])
        .map_err(|error| AppError::Internal(format!("failed to persist record: {error}")))?;

    Ok(())
}

fn load_json_row<T: DeserializeOwned>(
    db: &Arc<Mutex<Connection>>,
    table: &str,
    key_column: &str,
    key_value: &str,
) -> Result<Option<T>, AppError> {
    validate_sql_identifier(table)?;
    validate_sql_identifier(key_column)?;

    let connection = db
        .lock()
        .map_err(|_| AppError::Internal("database lock poisoned".to_string()))?;
    let statement = format!("SELECT payload_json FROM {table} WHERE {key_column} = ?1");
    let mut query = connection
        .prepare(&statement)
        .map_err(|error| AppError::Internal(format!("failed to prepare record lookup: {error}")))?;

    let payload: Option<String> = query
        .query_row([key_value], |row| row.get(0))
        .optional()
        .map_err(|error| AppError::Internal(format!("failed to query record: {error}")))?;

    payload
        .map(|payload| {
            serde_json::from_str(&payload)
                .map_err(|error| AppError::Internal(format!("failed to deserialize record: {error}")))
        })
        .transpose()
}

fn validate_sql_identifier(identifier: &str) -> Result<(), AppError> {
    let mut chars = identifier.chars();
    let Some(first) = chars.next() else {
        tracing::warn!("SQL identifier validation failed: empty identifier");
        return Err(AppError::Internal("invalid SQL identifier".to_string()));
    };

    if !(first == '_' || first.is_ascii_alphabetic()) {
        tracing::warn!(identifier = identifier, "SQL identifier validation failed: invalid first character");
        return Err(AppError::Internal("invalid SQL identifier".to_string()));
    }

    if !chars.all(|c| c == '_' || c.is_ascii_alphanumeric()) {
        tracing::warn!(identifier = identifier, "SQL identifier validation failed: invalid characters");
        return Err(AppError::Internal("invalid SQL identifier".to_string()));
    }

    Ok(())
}

fn take_json_row<T: DeserializeOwned>(
    db: &Arc<Mutex<Connection>>,
    table: &str,
    key_column: &str,
    key_value: &str,
) -> Result<Option<T>, AppError> {
    let record = load_json_row(db, table, key_column, key_value)?;
    if record.is_some() {
        let connection = db
            .lock()
            .map_err(|_| AppError::Internal("database lock poisoned".to_string()))?;
        let statement = format!("DELETE FROM {table} WHERE {key_column} = ?1");
        connection
            .execute(&statement, params![key_value])
            .map_err(|error| AppError::Internal(format!("failed to delete record: {error}")))?;
    }
    Ok(record)
}

pub fn generate_secret(len: usize) -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn now_plus_seconds(seconds: i64) -> chrono::DateTime<Utc> {
    Utc::now() + Duration::seconds(seconds)
}
