use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("authentication failed")]
    Authentication,
    #[error("not found")]
    NotFound,
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match self {
            AppError::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "validation_error",
                    message: msg,
                },
            ),
            AppError::Authentication => (
                StatusCode::UNAUTHORIZED,
                ErrorBody {
                    error: "authentication_error",
                    message: "Authentication failed".to_string(),
                },
            ),
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody {
                    error: "not_found",
                    message: "Requested resource not found".to_string(),
                },
            ),
            AppError::Upstream(msg) => (
                StatusCode::BAD_GATEWAY,
                ErrorBody {
                    error: "upstream_error",
                    message: msg,
                },
            ),
            AppError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "internal_error",
                    message: msg,
                },
            ),
        };

        (status, Json(body)).into_response()
    }
}
