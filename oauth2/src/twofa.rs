use serde::Deserialize;

use crate::error::AppError;
use crate::state::AppState;

fn validate_twofa_base_url(base_url: &str, environment: &str) -> Result<(), AppError> {
    let parsed = reqwest::Url::parse(base_url)
        .map_err(|_| AppError::Config("TWOFA_BASE_URL is not a valid URL".to_string()))?;

    if parsed.scheme() == "https" {
        return Ok(());
    }

    if !environment.eq_ignore_ascii_case("development") {
        return Err(AppError::Config(
            "TWOFA_BASE_URL must use HTTPS outside development".to_string(),
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
                | Some("twofa")
        );

    if is_allowed_dev_http {
        Ok(())
    } else {
        Err(AppError::Config(
            "TWOFA_BASE_URL must use HTTPS or an approved development loopback/host".to_string(),
        ))
    }
}

#[derive(Debug, Deserialize)]
pub struct TwoFactorStatus {
    pub account_id: String,
    pub two_factor_enabled: bool,
    pub hsk_enabled: bool,
    pub method: Option<String>,
}

pub async fn get_2fa_status(
    state: &AppState,
    account_id: &str,
    correlation_id: &str,
) -> Result<TwoFactorStatus, AppError> {
    let base_url = state
        .config
        .twofa_base_url
        .as_deref()
        .ok_or_else(|| AppError::Config("TWOFA_BASE_URL is not configured".to_string()))?;

    validate_twofa_base_url(base_url, &state.config.environment)?;

    let api_key = state
        .config
        .twofa_api_key
        .as_deref()
        .ok_or_else(|| AppError::Config("TWOFA_API_KEY is not configured".to_string()))?;

    let url = format!(
        "{}/api/status/{}",
        base_url.trim_end_matches('/'),
        account_id
    );

    let response = state
        .http_client
        .get(url)
        .bearer_auth(api_key)
        .header("x-correlation-id", correlation_id)
        .send()
        .await
        .map_err(|e| AppError::Upstream(format!("2fa request failed: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        return Err(AppError::Upstream(format!("2fa returned {status}: {body}")));
    }

    response
        .json::<TwoFactorStatus>()
        .await
        .map_err(|e| AppError::Upstream(format!("invalid 2fa response: {e}")))
}
