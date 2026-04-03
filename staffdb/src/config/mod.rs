// Configuration management for staffdb

use crate::error::{Error, Result};
use std::env;

pub mod security;

/// Application configuration loaded from environment
#[derive(Debug, Clone)]
pub struct Config {
    /// Server host to bind to (default: 127.0.0.1)
    pub host: String,

    /// Server port to bind to (default: 3000)
    pub port: u16,

    /// Database URL or path (SQLite format: sqlite:///path/to/db.sqlite or sqlite:db.sqlite)
    pub database_url: String,

    /// Service identifier for logging and audit purposes
    pub service_id: String,

    /// Environment (development, staging, production)
    pub environment: String,

    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,

    /// Allowed inbound service API credentials as `service_id:key` pairs.
    pub service_api_keys: Vec<(String, String)>,

    /// Service IDs allowed to call mutating endpoints.
    pub privileged_services: Vec<String>,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let host = env::var("STAFFDB_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = env::var("STAFFDB_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3000);

        let database_url = match env::var("DATABASE_URL") {
            Ok(value) => value,
            Err(_) => {
                // Default to SQLite in development
                match env::var("ENVIRONMENT").as_deref() {
                    Ok("production") => {
                        return Err(Error::ConfigError(
                            "DATABASE_URL is required in production".to_string(),
                        ));
                    }
                    _ => "sqlite:staffdb.sqlite".to_string(),
                }
            }
        };

        let service_id = env::var("SERVICE_ID").unwrap_or_else(|_| "staffdb".to_string());
        let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        let service_api_keys = env::var("SERVICE_API_KEYS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, ':');
                let service = parts.next()?.trim();
                let key = parts.next()?.trim();
                if service.is_empty() || key.is_empty() {
                    return None;
                }
                Some((service.to_string(), key.to_string()))
            })
            .collect::<Vec<_>>();

        let privileged_services = env::var("PRIVILEGED_SERVICES")
            .unwrap_or_else(|_| "admin,oauth2,staffdb".to_string())
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        let config = Config {
            host,
            port,
            database_url,
            service_id,
            environment,
            log_level,
            service_api_keys,
            privileged_services,
        };

        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values
    fn validate(&self) -> Result<()> {
        if self.port == 0 {
            return Err(Error::ConfigError("Port must be > 0".to_string()));
        }

        if self.database_url.is_empty() {
            return Err(Error::ConfigError("DATABASE_URL is required".to_string()));
        }

        if self.is_production() && self.service_api_keys.is_empty() {
            return Err(Error::ConfigError(
                "SERVICE_API_KEYS (service_id:key pairs) is required in production"
                    .to_string(),
            ));
        }

        if self.is_production()
            && self
                .service_api_keys
                .iter()
                .any(|(_, k)| k.eq_ignore_ascii_case("change_me"))
        {
            return Err(Error::ConfigError(
                "SERVICE_API_KEYS must not contain placeholder values in production"
                    .to_string(),
            ));
        }

        if self.privileged_services.is_empty() {
            return Err(Error::ConfigError(
                "PRIVILEGED_SERVICES must contain at least one service".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the full server address (host:port)
    pub fn server_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Check if running in production
    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let invalid = Config {
            host: "localhost".to_string(),
            port: 0,
            database_url: "sqlite:test.sqlite".to_string(),
            service_id: "test".to_string(),
            environment: "test".to_string(),
            log_level: "info".to_string(),
            service_api_keys: vec![("test".to_string(), "test-key".to_string())],
            privileged_services: vec!["test".to_string()],
        };

        assert!(invalid.validate().is_err());
    }
}
