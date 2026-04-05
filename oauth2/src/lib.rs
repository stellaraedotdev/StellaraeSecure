pub mod api;
pub mod config;
pub mod db;
pub mod error;
pub mod logger;
pub mod models;
pub mod staffdb;
pub mod state;
pub mod twofa;

use axum::Router;

use crate::config::Config;
use crate::error::AppError;
use crate::state::AppState;

pub fn app(config: &Config) -> Result<Router, AppError> {
    let state = AppState::new(config.clone())?;
    Ok(api::routes::router(state))
}
