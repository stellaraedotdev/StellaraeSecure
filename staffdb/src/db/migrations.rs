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
    create_rbac_roles_table(pool).await?;
    create_rbac_permissions_table(pool).await?;
    create_rbac_role_permissions_table(pool).await?;
    create_rbac_account_roles_table(pool).await?;
    ensure_accounts_two_factor_column(pool).await?;
    create_account_totp_factors_table(pool).await?;
    seed_system_rbac_roles(pool).await?;
    seed_oauth2_permissions(pool).await?;

    tracing::info!("Migrations completed successfully");
    Ok(())
}

async fn ensure_accounts_two_factor_column(pool: &SqlitePool) -> Result<()> {
    match sqlx::query(
        "ALTER TABLE accounts ADD COLUMN two_factor_enabled BOOLEAN NOT NULL DEFAULT false",
    )
    .execute(pool)
    .await
    {
        Ok(_) => {
            tracing::info!("accounts.two_factor_enabled column added");
        }
        Err(sqlx::Error::Database(error))
            if error.message().contains("duplicate column name") =>
        {
            tracing::debug!("accounts.two_factor_enabled column already exists");
        }
        Err(error) => return Err(error.into()),
    }

    Ok(())
}

async fn create_account_totp_factors_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS account_totp_factors (
            account_id TEXT PRIMARY KEY,
            secret_base32 TEXT NOT NULL,
            is_confirmed BOOLEAN NOT NULL DEFAULT false,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            last_verified_at DATETIME,
            FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_account_totp_confirmed ON account_totp_factors(is_confirmed)",
    )
    .execute(pool)
    .await?;

    tracing::info!("Account TOTP factor table created/verified");
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

/// Create rbac_roles table
async fn create_rbac_roles_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rbac_roles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            is_system BOOLEAN NOT NULL DEFAULT false,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_rbac_roles_name ON rbac_roles(name)")
        .execute(pool)
        .await?;

    tracing::info!("RBAC roles table created/verified");
    Ok(())
}

/// Create rbac_permissions table
async fn create_rbac_permissions_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rbac_permissions (
            id TEXT PRIMARY KEY,
            permission_key TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at DATETIME NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_rbac_permissions_key ON rbac_permissions(permission_key)",
    )
    .execute(pool)
    .await?;

    tracing::info!("RBAC permissions table created/verified");
    Ok(())
}

/// Create rbac_role_permissions mapping table
async fn create_rbac_role_permissions_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rbac_role_permissions (
            role_id TEXT NOT NULL,
            permission_id TEXT NOT NULL,
            granted_at DATETIME NOT NULL,
            PRIMARY KEY (role_id, permission_id),
            FOREIGN KEY (role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES rbac_permissions(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_rbac_role_permissions_role ON rbac_role_permissions(role_id)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_rbac_role_permissions_permission ON rbac_role_permissions(permission_id)",
    )
    .execute(pool)
    .await?;

    tracing::info!("RBAC role-permission mapping table created/verified");
    Ok(())
}

/// Create rbac_account_roles mapping table
async fn create_rbac_account_roles_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rbac_account_roles (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            role_id TEXT NOT NULL,
            granted_by TEXT,
            granted_at DATETIME NOT NULL,
            FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE,
            UNIQUE(account_id, role_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_rbac_account_roles_account ON rbac_account_roles(account_id)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_rbac_account_roles_role ON rbac_account_roles(role_id)",
    )
    .execute(pool)
    .await?;

    tracing::info!("RBAC account-role mapping table created/verified");
    Ok(())
}

/// Seed immutable baseline RBAC roles
async fn seed_system_rbac_roles(pool: &SqlitePool) -> Result<()> {
    let now = chrono::Utc::now();

    for role_name in ["super_admin", "security_admin", "support_readonly"] {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO rbac_roles (id, name, description, is_system, created_at, updated_at)
            VALUES (?, ?, ?, true, ?, ?)
            "#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(role_name)
        .bind(format!("System role: {}", role_name))
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;
    }

    tracing::info!("RBAC system role seeds created/verified");
    Ok(())
}

/// Seed OAuth2-related permission keys from oauth2 service
async fn seed_oauth2_permissions(pool: &SqlitePool) -> Result<()> {
    let oauth2_permissions = vec![
        ("oauth.client.create", "Create new OAuth2 client applications"),
        ("oauth.client.read", "Read OAuth2 client metadata"),
        ("oauth.client.secret.rotate", "Rotate client secrets (high-risk)"),
        ("oauth.client.delete", "Delete OAuth2 client applications (high-risk)"),
        ("oauth.client.collaborator.manage", "Manage client collaborators (high-risk)"),
        ("oauth.token.revoke", "Revoke access tokens (high-risk)"),
        ("oauth.token.introspect", "Introspect token metadata"),
        ("oauth.staff.authorize", "Authorize staff OAuth flows"),
        ("panel.audit.read", "Read admin audit events"),
        ("panel.session.issue", "Issue panel sessions"),
        ("panel.session.verify", "Validate panel sessions"),
    ];

    for (permission_key, description) in oauth2_permissions {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO rbac_permissions (id, permission_key, description, created_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(permission_key)
        .bind(description)
        .bind(chrono::Utc::now())
        .execute(pool)
        .await?;
    }

    tracing::info!("OAuth2 permission keys seeded/verified");
    Ok(())
}
