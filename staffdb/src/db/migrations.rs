// Database migrations for staffdb
// Run automatically on startup

use crate::error::Result;
use sqlx::SqlitePool;

/// Run all database migrations
pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    tracing::info!("Running database migrations");

    create_accounts_table(pool).await?;
    create_account_roles_table(pool).await?;
    create_audit_log_table(pool).await?;

    tracing::info!("Migrations completed successfully");
    Ok(())
}

/// Create accounts table
async fn create_accounts_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            is_active BOOLEAN NOT NULL DEFAULT true,
            account_type TEXT NOT NULL CHECK(account_type IN ('staff', 'user')),
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for common queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_accounts_is_active ON accounts(is_active)")
        .execute(pool)
        .await?;

    tracing::info!("Accounts table created/verified");
    Ok(())
}

/// Create account_roles junction table
async fn create_account_roles_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS account_roles (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'staff', 'user')),
            granted_at DATETIME NOT NULL,
            FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
            UNIQUE(account_id, role)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_account_roles_account ON account_roles(account_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_account_roles_role ON account_roles(role)")
        .execute(pool)
        .await?;

    tracing::info!("Account roles table created/verified");
    Ok(())
}

/// Create audit_log table (immutable)
async fn create_audit_log_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            action TEXT NOT NULL,
            actor_service TEXT NOT NULL,
            details TEXT,
            timestamp DATETIME NOT NULL,
            FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_account ON audit_log(account_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        .execute(pool)
        .await?;

    tracing::info!("Audit log table created/verified");
    Ok(())
}
