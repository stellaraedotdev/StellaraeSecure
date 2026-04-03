pub mod api;
pub mod config;
pub mod error;
pub mod logger;
pub mod models;
pub mod staffdb;
pub mod state;

use axum::Router;

use crate::config::Config;
use crate::state::AppState;

pub fn app(config: &Config) -> Router {
    let state = AppState::new(config.clone());
    api::routes::router(state)
}
