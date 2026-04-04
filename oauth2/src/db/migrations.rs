use rusqlite::{params, Connection};

use crate::error::AppError;

const MIGRATIONS: &[(&str, &str)] = &[("0001_initial", include_str!("../../migrations/0001_initial.sql"))];

pub fn run_migrations(connection: &Connection) -> Result<(), AppError> {
    connection
        .execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)",
            [],
        )
        .map_err(|error| AppError::Config(format!("failed to ensure schema_migrations table: {error}")))?;

    for (version, sql) in MIGRATIONS {
        let already_applied = connection
            .query_row(
                "SELECT 1 FROM schema_migrations WHERE version = ?1 LIMIT 1",
                [*version],
                |_| Ok(()),
            )
            .is_ok();

        if already_applied {
            continue;
        }

        let tx = connection
            .unchecked_transaction()
            .map_err(|error| AppError::Config(format!("failed to start migration transaction: {error}")))?;

        tx.execute_batch(sql)
            .map_err(|error| AppError::Config(format!("failed applying migration {version}: {error}")))?;

        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, datetime('now'))",
            params![version],
        )
        .map_err(|error| AppError::Config(format!("failed recording migration {version}: {error}")))?;

        tx.commit()
            .map_err(|error| AppError::Config(format!("failed committing migration {version}: {error}")))?;
    }

    Ok(())
}
