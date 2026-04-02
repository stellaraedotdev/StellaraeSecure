// Database connection pool initialization and management

use crate::error::{Error, Result};
use sqlx::{sqlite::SqlitePool, sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::time::Duration;

pub type DbPool = Pool<Sqlite>;

/// Initialize SQLite connection pool from DATABASE_URL
pub async fn create_pool(database_url: &str) -> Result<DbPool> {
    // Parse the database URL
    let connect_options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(parse_sqlite_path(database_url))
        .foreign_keys(true)
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(25)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(30))
        .connect_with(connect_options)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create database pool: {}", e);
            Error::DatabaseError(e)
        })?;

    tracing::info!("Database pool initialized with SQLite");

    Ok(pool)
}

/// Extract SQLite file path from database URL
/// Supports formats: sqlite:path/to/db.sqlite or sqlite:///abs/path/to/db.sqlite
fn parse_sqlite_path(url: &str) -> String {
    if let Some(path) = url.strip_prefix("sqlite://") {
        // sqlite:///absolute/path → /absolute/path
        // sqlite://relative/path → relative/path
        path.to_string()
    } else if let Some(path) = url.strip_prefix("sqlite:") {
        // sqlite:relative/path or sqlite:/path
        path.to_string()
    } else {
        url.to_string()
    }
}

/// Health check for database connectivity
pub async fn health_check(pool: &DbPool) -> Result<()> {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!("Database health check failed: {}", e);
            Error::DatabaseError(e)
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sqlite_path() {
        assert_eq!(parse_sqlite_path("sqlite:test.sqlite"), "test.sqlite");
        assert_eq!(
            parse_sqlite_path("sqlite:///absolute/path/db.sqlite"),
            "/absolute/path/db.sqlite"
        );
        assert_eq!(
            parse_sqlite_path("sqlite://relative/path/db.sqlite"),
            "relative/path/db.sqlite"
        );
    }
}
