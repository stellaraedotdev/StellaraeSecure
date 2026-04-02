// StellaraeSecure staffdb library
// Public interface for the account database service

pub mod config;
pub mod error;
pub mod logger;
pub mod models;
pub mod db;
pub mod auth;
pub mod api;

use std::sync::Arc;

pub use config::Config;
pub use error::{Error, Result};
pub use db::DbPool;

/// Application state holder
pub struct AppState {
    pub config: Config,
    pub db_pool: DbPool,
}

