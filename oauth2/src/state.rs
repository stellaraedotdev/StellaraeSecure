use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::config::Config;
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
    pub store: Arc<Mutex<MemoryStore>>,
    pub db: Arc<Mutex<Connection>>,
    pub http_client: reqwest::Client,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, AppError> {
        let database_url = normalize_sqlite_url(&config.database_url);
        let connection = Connection::open(database_url)
            .map_err(|error| AppError::Config(format!("failed to open oauth2 database: {error}")))?;
        initialize_schema(&connection)?;

        Self {
            config,
            store: Arc::new(Mutex::new(MemoryStore::default())),
            db: Arc::new(Mutex::new(connection)),
            http_client: reqwest::Client::new(),
        }
        .pipe(Ok)
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

fn initialize_schema(connection: &Connection) -> Result<(), AppError> {
    connection
        .execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS admin_audit_events (
                id TEXT PRIMARY KEY,
                actor_account_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_admin_audit_events_actor ON admin_audit_events(actor_account_id);
            CREATE INDEX IF NOT EXISTS idx_admin_audit_events_timestamp ON admin_audit_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_admin_audit_events_correlation ON admin_audit_events(correlation_id);

            CREATE TABLE IF NOT EXISTS panel_sessions (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                permissions_json TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_panel_sessions_account ON panel_sessions(account_id);
            CREATE INDEX IF NOT EXISTS idx_panel_sessions_expires ON panel_sessions(expires_at);
            "#,
        )
        .map_err(|error| AppError::Config(format!("failed to initialize oauth2 database schema: {error}")))?;

    Ok(())
}

trait Pipe: Sized {
    fn pipe<T, F: FnOnce(Self) -> T>(self, f: F) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

pub fn generate_secret(len: usize) -> String {
    thread_rng()
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
