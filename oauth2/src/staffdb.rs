use serde::Deserialize;

use crate::error::AppError;
use crate::state::AppState;

/// Validates that the staffdb base URL uses HTTPS (or approved dev loopbacks in development).
/// Prevents cleartext transmission of sensitive data like account IDs.
fn validate_secure_url(base_url: &str, environment: &str) -> Result<(), AppError> {
    let parsed = reqwest::Url::parse(base_url)
        .map_err(|_| AppError::Config("STAFFDB_BASE_URL is not a valid URL".to_string()))?;

    if parsed.scheme() == "https" {
        return Ok(());
    }

    if !environment.eq_ignore_ascii_case("development") {
        return Err(AppError::Config(
            "STAFFDB_BASE_URL must use HTTPS outside development".to_string(),
        ));
    }

    let is_allowed_dev_http = parsed.scheme() == "http"
        && matches!(
            parsed.host_str(),
            Some("localhost")
                | Some("127.0.0.1")
                | Some("::1")
                | Some("[::1]")
                | Some("host.docker.internal")
                | Some("staffdb")
        );

    if is_allowed_dev_http {
        Ok(())
    } else {
        Err(AppError::Config(
            "STAFFDB_BASE_URL must use HTTPS or an approved development loopback/host"
                .to_string(),
        ))
    }
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

#[cfg(test)]
mod tests {
    use super::validate_secure_url;

    #[test]
    fn staffdb_url_validation_allows_expected_development_hosts() {
        for url in [
            "https://staffdb.example.com",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://[::1]:3000",
            "http://host.docker.internal:3000",
            "http://staffdb:3000",
        ] {
            assert!(validate_secure_url(url, "development").is_ok(), "{url}");
        }
    }

    #[test]
    fn staffdb_url_validation_rejects_unapproved_hosts_and_schemes() {
        for url in [
            "http://example.com",
            "ftp://staffdb.example.com",
            "http://127.0.0.1.evil.com",
            "http://127.0.0.1@evil.com",
        ] {
            assert!(validate_secure_url(url, "development").is_err(), "{url}");
        }
    }

    #[test]
    fn staffdb_url_validation_enforces_https_outside_development() {
        assert!(validate_secure_url("https://staffdb.example.com", "production").is_ok());
        assert!(validate_secure_url("http://localhost:3000", "production").is_err());
        assert!(validate_secure_url("http://staffdb:3000", "Production").is_err());
    }

    #[test]
    fn staffdb_url_validation_treats_development_case_insensitively() {
        assert!(validate_secure_url("http://localhost:3000", "development").is_ok());
        assert!(validate_secure_url("http://localhost:3000", "Development").is_ok());
        assert!(validate_secure_url("http://localhost:3000", "DEVELOPMENT").is_ok());
    }
}
