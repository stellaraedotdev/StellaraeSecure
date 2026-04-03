// API middleware for request processing

use crate::auth::{extract_api_key, validate_service_key};
use crate::error::Error;
use axum::{
    extract::State,
    extract::Request,
    http::HeaderMap,
    http::Method,
    middleware::Next,
    response::Response,
};
use governor::DefaultKeyedRateLimiter;
use std::num::NonZeroU32;
use std::sync::OnceLock;

use crate::AppState;

#[derive(Clone, Debug)]
pub struct AuthenticatedService {
    pub id: String,
}

/// Rate limiter (10,000 requests per second per service)
fn rate_limiter() -> &'static DefaultKeyedRateLimiter<String> {
    static LIMITER: OnceLock<DefaultKeyedRateLimiter<String>> = OnceLock::new();
    LIMITER.get_or_init(|| {
        governor::RateLimiter::keyed(governor::Quota::per_second(
            NonZeroU32::new(10_000).expect("non-zero quota"),
        ))
    })
}

fn is_mutating_api_route(method: &Method, path: &str) -> bool {
    path.starts_with("/api/") && *method != Method::GET && *method != Method::HEAD
}

/// Service authentication middleware
/// Validates Authorization header and extracts service identity
pub async fn service_auth(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, Error> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::AuthenticationError("Missing Authorization header".to_string()))?;

    let api_key = extract_api_key(auth_header)?;
    let caller_service_id = validate_service_key(&api_key, &state.config.service_api_keys)?;

    if rate_limiter().check_key(&caller_service_id).is_err() {
        return Err(Error::RateLimited);
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    if is_mutating_api_route(&method, &path)
        && !state
            .config
            .privileged_services
            .iter()
            .any(|svc| svc == &caller_service_id)
    {
        return Err(Error::AuthorizationError(
            "Service is not allowed to mutate account data".to_string(),
        ));
    }

    let mut req = req;
    req.extensions_mut().insert(AuthenticatedService {
        id: caller_service_id,
    });

    tracing::debug!("Service authentication passed");

    Ok(next.run(req).await)
}
