use serde::Deserialize;

use crate::error::AppError;
use crate::state::AppState;

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
