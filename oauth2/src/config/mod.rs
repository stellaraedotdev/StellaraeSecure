use std::env;
use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionEnforcementMode {
    Off,
    Observe,
    Enforce,
}

impl PermissionEnforcementMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PermissionEnforcementMode::Off => "off",
            PermissionEnforcementMode::Observe => "observe",
            PermissionEnforcementMode::Enforce => "enforce",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub host: IpAddr,
    pub port: u16,
    pub environment: String,
    pub service_id: String,
    pub log_level: String,
    pub database_url: String,
    pub issuer: String,
    pub admin_api_key: String,
    pub staffdb_base_url: String,
    pub staffdb_api_key: String,
    pub access_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
    pub auth_code_ttl_seconds: i64,
    pub panel_session_ttl_seconds: i64,
    pub permission_enforcement_mode: PermissionEnforcementMode,
    pub staff_identity_hmac_secret: String,
    pub staff_identity_max_skew_seconds: i64,
    pub stepup_session_freshness_seconds: i64,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingVar(&'static str),
    #[error("invalid value for environment variable {name}: {value}")]
    InvalidVar { name: &'static str, value: String },
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let host = env::var("OAUTH2_HOST")
            .unwrap_or_else(|_| "127.0.0.1".to_string())
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::InvalidVar {
                name: "OAUTH2_HOST",
                value: env::var("OAUTH2_HOST").unwrap_or_default(),
            })?;

        let port = env::var("OAUTH2_PORT")
            .unwrap_or_else(|_| "4000".to_string())
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidVar {
                name: "OAUTH2_PORT",
                value: env::var("OAUTH2_PORT").unwrap_or_default(),
            })?;

        let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        let service_id = env::var("SERVICE_ID").unwrap_or_else(|_| "oauth2-dev".to_string());
        let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());

        let database_url = env::var("DATABASE_URL")
            .map_err(|_| ConfigError::MissingVar("DATABASE_URL"))?;

        let issuer = env::var("OAUTH2_ISSUER")
            .unwrap_or_else(|_| "https://secure.stellarae.org/oauth2/public".to_string());

        let admin_api_key = env::var("OAUTH2_ADMIN_API_KEY")
            .map_err(|_| ConfigError::MissingVar("OAUTH2_ADMIN_API_KEY"))?;

        let staffdb_base_url = env::var("STAFFDB_BASE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());

        let staffdb_api_key = env::var("STAFFDB_API_KEY")
            .map_err(|_| ConfigError::MissingVar("STAFFDB_API_KEY"))?;

        let access_token_ttl_seconds = env::var("OAUTH2_ACCESS_TOKEN_TTL_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse::<i64>()
            .map_err(|_| ConfigError::InvalidVar {
                name: "OAUTH2_ACCESS_TOKEN_TTL_SECONDS",
                value: env::var("OAUTH2_ACCESS_TOKEN_TTL_SECONDS").unwrap_or_default(),
            })?;

        let refresh_token_ttl_seconds = env::var("OAUTH2_REFRESH_TOKEN_TTL_SECONDS")
            .unwrap_or_else(|_| "2592000".to_string())
            .parse::<i64>()
            .map_err(|_| ConfigError::InvalidVar {
                name: "OAUTH2_REFRESH_TOKEN_TTL_SECONDS",
                value: env::var("OAUTH2_REFRESH_TOKEN_TTL_SECONDS").unwrap_or_default(),
            })?;

        let auth_code_ttl_seconds = env::var("OAUTH2_AUTH_CODE_TTL_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<i64>()
            .map_err(|_| ConfigError::InvalidVar {
                name: "OAUTH2_AUTH_CODE_TTL_SECONDS",
                value: env::var("OAUTH2_AUTH_CODE_TTL_SECONDS").unwrap_or_default(),
            })?;

        let panel_session_ttl_seconds = env::var("OAUTH2_PANEL_SESSION_TTL_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse::<i64>()
            .map_err(|_| ConfigError::InvalidVar {
                name: "OAUTH2_PANEL_SESSION_TTL_SECONDS",
                value: env::var("OAUTH2_PANEL_SESSION_TTL_SECONDS").unwrap_or_default(),
            })?;

        let staff_identity_hmac_secret = env::var("OAUTH2_STAFF_IDENTITY_HMAC_SECRET")
            .map_err(|_| ConfigError::MissingVar("OAUTH2_STAFF_IDENTITY_HMAC_SECRET"))?;

        let staff_identity_max_skew_seconds = env::var("OAUTH2_STAFF_IDENTITY_MAX_SKEW_SECONDS")
            .unwrap_or_else(|_| "120".to_string())
            .parse::<i64>()
            .map_err(|_| ConfigError::InvalidVar {
                name: "OAUTH2_STAFF_IDENTITY_MAX_SKEW_SECONDS",
                value: env::var("OAUTH2_STAFF_IDENTITY_MAX_SKEW_SECONDS").unwrap_or_default(),
            })?;

        if staff_identity_max_skew_seconds <= 0 {
            return Err(ConfigError::InvalidVar {
                name: "OAUTH2_STAFF_IDENTITY_MAX_SKEW_SECONDS",
                value: staff_identity_max_skew_seconds.to_string(),
            });
        }

        let default_mode = if environment.eq_ignore_ascii_case("development") {
            "observe"
        } else {
            "enforce"
        };

        let permission_enforcement_mode = match env::var("OAUTH2_PERMISSION_ENFORCEMENT_MODE")
            .unwrap_or_else(|_| default_mode.to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "off" => PermissionEnforcementMode::Off,
            "observe" => PermissionEnforcementMode::Observe,
            "enforce" => PermissionEnforcementMode::Enforce,
            _ => {
                return Err(ConfigError::InvalidVar {
                    name: "OAUTH2_PERMISSION_ENFORCEMENT_MODE",
                    value: env::var("OAUTH2_PERMISSION_ENFORCEMENT_MODE").unwrap_or_default(),
                })
            }
        };

        let stepup_session_freshness_seconds = env::var("OAUTH2_STEPUP_SESSION_FRESHNESS_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<i64>()
            .map_err(|_| ConfigError::InvalidVar {
                name: "OAUTH2_STEPUP_SESSION_FRESHNESS_SECONDS",
                value: env::var("OAUTH2_STEPUP_SESSION_FRESHNESS_SECONDS").unwrap_or_default(),
            })?;

        if stepup_session_freshness_seconds <= 0 {
            return Err(ConfigError::InvalidVar {
                name: "OAUTH2_STEPUP_SESSION_FRESHNESS_SECONDS",
                value: stepup_session_freshness_seconds.to_string(),
            });
        }

        Ok(Self {
            host,
            port,
            environment,
            service_id,
            log_level,
            database_url,
            issuer,
            admin_api_key,
            staffdb_base_url,
            staffdb_api_key,
            access_token_ttl_seconds,
            refresh_token_ttl_seconds,
            auth_code_ttl_seconds,
            panel_session_ttl_seconds,
            permission_enforcement_mode,
            staff_identity_hmac_secret,
            staff_identity_max_skew_seconds,
            stepup_session_freshness_seconds,
        })
    }
}
