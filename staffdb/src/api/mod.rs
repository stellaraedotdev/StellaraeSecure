// REST API routes and handlers
// Phase 4: Account and role management endpoints

pub mod handlers;
pub mod middleware;

use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use std::sync::Arc;

use crate::AppState;

/// Build the API router with all handlers
pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        // Account endpoints
        .route("/accounts", post(handlers::accounts::create_account))
        .route("/accounts/lookup", get(handlers::accounts::lookup_account))
        .route("/accounts/:id", get(handlers::accounts::get_account))
        .route("/accounts/:id", patch(handlers::accounts::update_account))
        .route("/accounts/:id", delete(handlers::accounts::delete_account))
        
        // Role endpoints
        .route(
            "/accounts/:id/roles",
            post(handlers::roles::grant_role)
                .get(handlers::roles::get_roles),
        )
        .route(
            "/accounts/:id/roles/:role",
            delete(handlers::roles::revoke_role),
        )
        
        // Audit endpoints
        .route("/audit/accounts/:id", get(handlers::audit::get_audit_log))
        
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::service_auth,
        ))
        .with_state(state)
}
