// API middleware for request processing

use crate::auth::{extract_api_key, validate_service_key};
use crate::error::Error;
use axum::{
    extract::State,
    extract::Request,
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use governor::RateLimiter;
use std::num::NonZeroU32;
use std::sync::OnceLock;

use crate::AppState;

#[derive(Clone, Debug)]
pub struct AuthenticatedService {
    pub id: String,
}

/// Rate limiter (10,000 requests per second per service)
fn rate_limiter() -> &'static RateLimiter {
    static LIMITER: OnceLock<RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| {
        RateLimiter::direct(governor::Quota::per_second(
            NonZeroU32::new(10_000).expect("non-zero quota"),
        ))
    })
}

/// Service authentication middleware
/// Validates Authorization header and extracts service identity
pub async fn service_auth(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, Error> {
    // Check rate limit first
    if rate_limiter().check().is_err() {
        return Err(Error::RateLimited);
    }

    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::AuthenticationError("Missing Authorization header".to_string()))?;

    let api_key = extract_api_key(auth_header)?;
    validate_service_key(&api_key, &state.config.service_api_keys)?;

    let caller_service_id = headers
        .get("X-Service-Id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown-service")
        .to_string();

    let mut req = req;
    req.extensions_mut().insert(AuthenticatedService {
        id: caller_service_id,
    });

    tracing::debug!("Service authentication passed");

    Ok(next.run(req).await)
}
