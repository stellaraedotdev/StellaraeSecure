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
pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
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

        // RBAC endpoints
        .route(
            "/rbac/roles",
            post(handlers::rbac::create_role)
                .get(handlers::rbac::list_roles),
        )
        .route(
            "/rbac/permissions",
            post(handlers::rbac::create_permission)
                .get(handlers::rbac::list_permissions),
        )
        .route(
            "/rbac/roles/:role_id/permissions",
            post(handlers::rbac::assign_permission_to_role),
        )
        .route(
            "/rbac/accounts/:account_id/roles",
            post(handlers::rbac::assign_role_to_account)
                .get(handlers::rbac::list_account_roles),
        )
        .route(
            "/rbac/accounts/:account_id/roles/:role_id",
            delete(handlers::rbac::revoke_role_from_account),
        )
        .route(
            "/rbac/accounts/:account_id/permissions/effective",
            get(handlers::rbac::get_effective_permissions),
        )

        // 2FA endpoints
        .route(
            "/2fa/totp/:account_id/enroll",
            post(handlers::twofa::enroll_totp),
        )
        .route(
            "/2fa/totp/:account_id/verify",
            post(handlers::twofa::verify_totp),
        )
        .route(
            "/2fa/hsk/:account_id/challenge",
            post(handlers::twofa::start_hsk_challenge),
        )
        .route(
            "/2fa/hsk/:account_id/verify",
            post(handlers::twofa::verify_hsk_challenge),
        )
        .route(
            "/2fa/status/:account_id",
            get(handlers::twofa::get_2fa_status),
        )
        
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::service_auth,
        ))
}
