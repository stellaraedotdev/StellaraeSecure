// Repository trait definitions and implementations for storage abstraction
// Designed for SQLite first, PostgreSQL later (just swap implementations)

use crate::models::{Account, AuditEvent, Role};
use crate::error::Result;
use serde_json::json;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;
use chrono::Utc;

/// Repository trait for account operations
#[async_trait::async_trait]
pub trait AccountRepository {
    /// Create a new account
    async fn create_account(
        &self,
        username: &str,
        email: &str,
        password_hash: &str,
        account_type: &str,
    ) -> Result<Account>;

    /// Get account by ID
    async fn get_account(&self, account_id: &str) -> Result<Option<Account>>;

    /// Get account by username or email
    async fn get_account_by_username(&self, username: &str) -> Result<Option<Account>>;
    async fn get_account_by_email(&self, email: &str) -> Result<Option<Account>>;

    /// Update account (selective fields)
    async fn update_account(&self, account_id: &str, email: Option<&str>, is_active: Option<bool>) -> Result<Account>;

    /// List all accounts (with pagination for Phase 5)
    async fn list_accounts(&self, limit: i32, offset: i32) -> Result<Vec<Account>>;

    /// Count total accounts
    async fn count_accounts(&self) -> Result<i64>;
}

/// Repository trait for role operations
#[async_trait::async_trait]
pub trait RoleRepository {
    /// Grant a role to an account
    async fn grant_role(&self, account_id: &str, role: &str) -> Result<()>;

    /// Revoke a role from an account
    async fn revoke_role(&self, account_id: &str, role: &str) -> Result<()>;

    /// Get all roles for an account
    async fn get_roles(&self, account_id: &str) -> Result<Vec<Role>>;

    /// Check if account has a specific role
    async fn has_role(&self, account_id: &str, role: &str) -> Result<bool>;
}

/// Repository trait for audit events
#[async_trait::async_trait]
pub trait AuditLogRepository {
    /// Record an immutable audit event
    async fn log_event(&self, account_id: &str, action: &str, actor_service: &str, details: Option<serde_json::Value>) -> Result<AuditEvent>;

    /// Get audit events for an account
    async fn get_events(&self, account_id: &str, limit: i32, offset: i32) -> Result<Vec<AuditEvent>>;

    /// Count audit events for an account
    async fn count_events(&self, account_id: &str) -> Result<i64>;
}

// --- SQLite Implementation ---

/// SQLite repository implementation
pub struct SqliteAccountRepository {
    pool: SqlitePool,
}

impl SqliteAccountRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl AccountRepository for SqliteAccountRepository {
    async fn create_account(
        &self,
        username: &str,
        email: &str,
        password_hash: &str,
        account_type: &str,
    ) -> Result<Account> {
        let account_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO accounts (id, username, email, password_hash, created_at, updated_at, is_active, account_type)
            VALUES (?, ?, ?, ?, ?, ?, true, ?)
            "#,
        )
        .bind(&account_id)
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind(now)
        .bind(now)
        .bind(account_type)
        .execute(&self.pool)
        .await?;

        Ok(Account {
            id: account_id,
            username: username.to_string(),
            email: email.to_string(),
            password_hash: Some(password_hash.to_string()),
            is_active: true,
            account_type: account_type.to_string(),
            created_at: now,
            updated_at: now,
        })
    }

    async fn get_account(&self, account_id: &str) -> Result<Option<Account>> {
        let row = sqlx::query(
            r#"
            SELECT id, username, email, password_hash, is_active, account_type, created_at, updated_at
            FROM accounts
            WHERE id = ?
            "#,
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| Account {
            id: r.get("id"),
            username: r.get("username"),
            email: r.get("email"),
            password_hash: r.get("password_hash"),
            is_active: r.get("is_active"),
            account_type: r.get("account_type"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    async fn get_account_by_username(&self, username: &str) -> Result<Option<Account>> {
        let row = sqlx::query(
            r#"
            SELECT id, username, email, password_hash, is_active, account_type, created_at, updated_at
            FROM accounts
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| Account {
            id: r.get("id"),
            username: r.get("username"),
            email: r.get("email"),
            password_hash: r.get("password_hash"),
            is_active: r.get("is_active"),
            account_type: r.get("account_type"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    async fn get_account_by_email(&self, email: &str) -> Result<Option<Account>> {
        let row = sqlx::query(
            r#"
            SELECT id, username, email, password_hash, is_active, account_type, created_at, updated_at
            FROM accounts
            WHERE email = ?
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| Account {
            id: r.get("id"),
            username: r.get("username"),
            email: r.get("email"),
            password_hash: r.get("password_hash"),
            is_active: r.get("is_active"),
            account_type: r.get("account_type"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    async fn update_account(&self, account_id: &str, email: Option<&str>, is_active: Option<bool>) -> Result<Account> {
        let now = Utc::now();

        if let Some(new_email) = email {
            sqlx::query("UPDATE accounts SET email = ?, updated_at = ? WHERE id = ?")
                .bind(new_email)
                .bind(now)
                .bind(account_id)
                .execute(&self.pool)
                .await?;
        }

        if let Some(active) = is_active {
            sqlx::query("UPDATE accounts SET is_active = ?, updated_at = ? WHERE id = ?")
                .bind(active)
                .bind(now)
                .bind(account_id)
                .execute(&self.pool)
                .await?;
        }

        self.get_account(account_id)
            .await?
            .ok_or(crate::error::Error::NotFound)
    }

    async fn list_accounts(&self, limit: i32, offset: i32) -> Result<Vec<Account>> {
        let rows = sqlx::query(
            r#"
            SELECT id, username, email, password_hash, is_active, account_type, created_at, updated_at
            FROM accounts
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| Account {
                id: r.get("id"),
                username: r.get("username"),
                email: r.get("email"),
                password_hash: r.get("password_hash"),
                is_active: r.get("is_active"),
                account_type: r.get("account_type"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }

    async fn count_accounts(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM accounts")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("count"))
    }
}

pub struct SqliteRoleRepository {
    pool: SqlitePool,
}

impl SqliteRoleRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl RoleRepository for SqliteRoleRepository {
    async fn grant_role(&self, account_id: &str, role: &str) -> Result<()> {
        let role_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT OR IGNORE INTO account_roles (id, account_id, role, granted_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&role_id)
        .bind(account_id)
        .bind(role)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn revoke_role(&self, account_id: &str, role: &str) -> Result<()> {
        sqlx::query("DELETE FROM account_roles WHERE account_id = ? AND role = ?")
            .bind(account_id)
            .bind(role)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn get_roles(&self, account_id: &str) -> Result<Vec<Role>> {
        let rows = sqlx::query("SELECT id, role, granted_at FROM account_roles WHERE account_id = ?")
            .bind(account_id)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| Role {
                id: r.get("id"),
                role: r.get("role"),
                granted_at: r.get("granted_at"),
            })
            .collect())
    }

    async fn has_role(&self, account_id: &str, role: &str) -> Result<bool> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM account_roles WHERE account_id = ? AND role = ?",
        )
        .bind(account_id)
        .bind(role)
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0 > 0)
    }
}

pub struct SqliteAuditLogRepository {
    pool: SqlitePool,
}

impl SqliteAuditLogRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl AuditLogRepository for SqliteAuditLogRepository {
    async fn log_event(&self, account_id: &str, action: &str, actor_service: &str, details: Option<serde_json::Value>) -> Result<AuditEvent> {
        let event_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let details_json = details.unwrap_or_else(|| json!({}));

        sqlx::query(
            r#"
            INSERT INTO audit_log (id, account_id, action, actor_service, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&event_id)
        .bind(account_id)
        .bind(action)
        .bind(actor_service)
        .bind(details_json.to_string())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(AuditEvent {
            id: event_id,
            account_id: account_id.to_string(),
            action: action.to_string(),
            actor_service: actor_service.to_string(),
            details: Some(details_json),
            timestamp: now,
        })
    }

    async fn get_events(&self, account_id: &str, limit: i32, offset: i32) -> Result<Vec<AuditEvent>> {
        let rows = sqlx::query(
            r#"
            SELECT id, account_id, action, actor_service, details, timestamp
            FROM audit_log
            WHERE account_id = ?
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(account_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let details_str: String = r.get("details");
                let details = serde_json::from_str(&details_str).ok();

                AuditEvent {
                    id: r.get("id"),
                    account_id: r.get("account_id"),
                    action: r.get("action"),
                    actor_service: r.get("actor_service"),
                    details,
                    timestamp: r.get("timestamp"),
                }
            })
            .collect())
    }

    async fn count_events(&self, account_id: &str) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM audit_log WHERE account_id = ?")
            .bind(account_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("count"))
    }
}
