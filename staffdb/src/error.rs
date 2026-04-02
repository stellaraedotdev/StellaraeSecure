// Error handling for staffdb service

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Result type for staffdb operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for staffdb service
#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Authorization error: {0}")]
    AuthorizationError(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Not found")]
    NotFound,

    #[error("Internal server error")]
    InternalServerError,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Error::ConfigError(ref msg) => {
                tracing::error!("Configuration error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error")
            }
            Error::DatabaseError(ref err) => {
                tracing::error!("Database error: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
            }
            Error::ValidationError(ref msg) => {
                tracing::warn!("Validation error: {}", msg);
                (StatusCode::BAD_REQUEST, "Validation error")
            }
            Error::AuthenticationError(ref msg) => {
                tracing::warn!("Authentication error: {}", msg);
                (StatusCode::UNAUTHORIZED, "Authentication error")
            }
            Error::AuthorizationError(ref msg) => {
                tracing::warn!("Authorization error: {}", msg);
                (StatusCode::FORBIDDEN, "Authorization error")
            }
            Error::RateLimited => {
                tracing::warn!("Rate limit exceeded");
                (StatusCode::TOO_MANY_REQUESTS, "Rate limited")
            }
            Error::NotFound => (StatusCode::NOT_FOUND, "Not found"),
            Error::InternalServerError => {
                tracing::error!("Internal server error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16(),
        }));

        (status, body).into_response()
    }
}
