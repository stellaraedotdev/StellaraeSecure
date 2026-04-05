use serde::Deserialize;

use crate::error::AppError;
use crate::state::AppState;

/// Validates that the staffdb base URL uses HTTPS (or approved dev loopbacks in development).
/// Prevents cleartext transmission of sensitive data like account IDs.
fn validate_secure_url(base_url: &str, environment: &str) -> Result<(), AppError> {
    // Production: Always require HTTPS
    if environment != "development" {
        if !base_url.starts_with("https://") {
            return Err(AppError::Internal(
                format!("Insecure transport to staffdb: {} does not use HTTPS in {} environment", base_url, environment)
            ));
        }
        return Ok(());
    }

    // Development: Allow HTTPS, localhost variants, and docker service names
    let allowed_schemes = [
        "https://",
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",  // IPv6 loopback
        "http://host.docker.internal",
        "http://staffdb",  // Docker compose service name
    ];

    if allowed_schemes.iter().any(|scheme| base_url.starts_with(scheme)) {
        return Ok(());
    }

    Err(AppError::Internal(
        format!(
            "Insecure or invalid transport to staffdb: {}. Development allows HTTPS, localhost, 127.0.0.1, [::1], host.docker.internal, or staffdb service name",
            base_url
        )
    ))
}

#[derive(Debug, Deserialize)]
pub struct StaffAccount {
    pub id: String,
    pub username: String,
    pub email: String,
    pub is_active: bool,
    pub account_type: String,
    #[serde(default)]
    pub two_factor_enabled: bool,
    #[serde(default)]
    pub hsk_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct EffectivePermissions {
    pub account_id: String,
    pub permissions: Vec<String>,
}

pub async fn lookup_account(
    state: &AppState,
    username: Option<&str>,
    email: Option<&str>,
    correlation_id: &str,
) -> Result<StaffAccount, AppError> {
    validate_secure_url(&state.config.staffdb_base_url, &state.config.environment)?;
    let mut url = format!("{}/api/accounts/lookup", state.config.staffdb_base_url.trim_end_matches('/'));

    let mut params = vec![];
    if let Some(v) = username {
        params.push(("username", v));
    }
    if let Some(v) = email {
        params.push(("email", v));
    }

    if params.is_empty() {
        return Err(AppError::Validation("username or email is required".to_string()));
    }

    let query = serde_urlencoded::to_string(params)
        .map_err(|e| AppError::Internal(format!("failed to build staffdb query: {e}")))?;
    url = format!("{url}?{query}");

    let response = state
        .http_client
        .get(url)
        .bearer_auth(&state.config.staffdb_api_key)
        .header("x-correlation-id", correlation_id)
        .send()
        .await
        .map_err(|e| AppError::Upstream(format!("staffdb request failed: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(AppError::Upstream(format!(
            "staffdb returned {status}: {body}"
        )));
    }

    response
        .json::<StaffAccount>()
        .await
        .map_err(|e| AppError::Upstream(format!("invalid staffdb response: {e}")))
}

pub async fn get_account_by_id(
    state: &AppState,
    account_id: &str,
    correlation_id: &str,
) -> Result<StaffAccount, AppError> {
    validate_secure_url(&state.config.staffdb_base_url, &state.config.environment)?;
    let url = format!(
        "{}/api/accounts/{}",
        state.config.staffdb_base_url.trim_end_matches('/'),
        account_id
    );

    let response = state
        .http_client
        .get(url)
        .bearer_auth(&state.config.staffdb_api_key)
        .header("x-correlation-id", correlation_id)
        .send()
        .await
        .map_err(|e| AppError::Upstream(format!("staffdb request failed: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(AppError::Upstream(format!(
            "staffdb returned {status}: {body}"
        )));
    }

    response
        .json::<StaffAccount>()
        .await
        .map_err(|e| AppError::Upstream(format!("invalid staffdb response: {e}")))
}

pub async fn get_effective_permissions(
    state: &AppState,
    account_id: &str,
    correlation_id: &str,
) -> Result<EffectivePermissions, AppError> {
    validate_secure_url(&state.config.staffdb_base_url, &state.config.environment)?;
    let url = format!(
        "{}/api/rbac/accounts/{}/permissions/effective",
        state.config.staffdb_base_url.trim_end_matches('/'),
        account_id
    );

    let response = state
        .http_client
        .get(url)
        .bearer_auth(&state.config.staffdb_api_key)
        .header("x-correlation-id", correlation_id)
        .send()
        .await
        .map_err(|e| AppError::Upstream(format!("staffdb request failed: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(AppError::Upstream(format!(
            "staffdb returned {status}: {body}"
        )));
    }

    response
        .json::<EffectivePermissions>()
        .await
        .map_err(|e| AppError::Upstream(format!("invalid staffdb response: {e}")))
}
