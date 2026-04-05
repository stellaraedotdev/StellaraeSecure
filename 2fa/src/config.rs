use std::{env, net::IpAddr};

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: IpAddr,
    pub port: u16,
    pub database_url: String,
    pub service_id: String,
    pub log_level: String,
    pub twofa_api_key: String,
    pub staffdb_base_url: Option<String>,
    pub staffdb_api_key: Option<String>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingVar(&'static str),
    #[error("invalid value for environment variable {name}: {value}")]
    InvalidVar { name: &'static str, value: String },
}

fn optional_non_empty(var: &'static str) -> Option<String> {
    env::var(var)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let host = env::var("TWOFA_HOST")
            .unwrap_or_else(|_| "127.0.0.1".to_string())
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::InvalidVar {
                name: "TWOFA_HOST",
                value: env::var("TWOFA_HOST").unwrap_or_default(),
            })?;

        let port = env::var("TWOFA_PORT")
            .unwrap_or_else(|_| "4100".to_string())
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidVar {
                name: "TWOFA_PORT",
                value: env::var("TWOFA_PORT").unwrap_or_default(),
            })?;

        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite:twofa.sqlite".to_string());

        let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        let service_id = env::var("SERVICE_ID").unwrap_or_else(|_| "twofa-dev".to_string());
        let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());

        let twofa_api_key = env::var("TWOFA_API_KEY")
            .map_err(|_| ConfigError::MissingVar("TWOFA_API_KEY"))?;

        let staffdb_base_url = optional_non_empty("STAFFDB_BASE_URL");
        let staffdb_api_key = optional_non_empty("STAFFDB_API_KEY");

        // Validate staffdb transport: HTTPS everywhere, with explicit HTTP exceptions in development.
        if let Some(ref url) = staffdb_base_url {
            let parsed = reqwest::Url::parse(url).map_err(|_| ConfigError::InvalidVar {
                name: "STAFFDB_BASE_URL",
                value: "must be a valid URL".to_string(),
            })?;

            let is_https = parsed.scheme() == "https";
            let is_development = environment.eq_ignore_ascii_case("development");
            let is_allowed_dev_http = parsed.scheme() == "http"
                && is_development
                && matches!(
                    parsed.host_str(),
                    Some("staffdb")
                        | Some("localhost")
                        | Some("127.0.0.1")
                        | Some("::1")
                        | Some("[::1]")
                        | Some("host.docker.internal")
                );

            if !is_https && !is_allowed_dev_http {
                return Err(ConfigError::InvalidVar {
                    name: "STAFFDB_BASE_URL",
                    value:
                        "Must use HTTPS, or in development use HTTP with staffdb/localhost/127.0.0.1/[::1]/host.docker.internal"
                            .to_string(),
                });
            }
        }

        Ok(Self {
            host,
            port,
            database_url,
            service_id,
            log_level,
            twofa_api_key,
            staffdb_base_url,
            staffdb_api_key,
        })
    }
}
