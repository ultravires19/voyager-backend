//! Error utilities
//! This module defines the application's error types and conversions

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::fmt;

use crate::auth::db::DbError;

/// Application error type
#[derive(Debug)]
pub enum AppError {
    /// Authentication errors
    Auth(String),
    /// Database errors
    Database(DbError),
    /// Validation errors
    Validation(String),
    /// Not found errors
    NotFound(String),
    /// Internal server errors
    Internal(String),
    /// Token errors
    Token(String),
    /// Request rate limited
    RateLimited(String),
    /// Forbidden - lacks permission
    Forbidden(String),
}

/// Application result type
pub type Result<T> = std::result::Result<T, AppError>;

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Auth(msg) => write!(f, "Authentication error: {}", msg),
            AppError::Database(err) => write!(f, "Database error: {}", err),
            AppError::Validation(msg) => write!(f, "Validation error: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::Internal(msg) => write!(f, "Internal error: {}", msg),
            AppError::Token(msg) => write!(f, "Token error: {}", msg),
            AppError::RateLimited(msg) => write!(f, "Rate limited: {}", msg),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_type, error_message) = match self {
            AppError::Auth(msg) => (StatusCode::UNAUTHORIZED, "authentication_error", msg),
            AppError::Database(err) => match err {
                DbError::UserNotFound => (
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "User not found".to_string(),
                ),
                DbError::EmailExists => (
                    StatusCode::CONFLICT,
                    "conflict",
                    "Email already registered".to_string(),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "Database error".to_string(),
                ),
            },
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, "validation_error", msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", msg),
            AppError::Token(msg) => (StatusCode::BAD_REQUEST, "token_error", msg),
            AppError::RateLimited(msg) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg),
        };

        // Log errors based on severity
        match status {
            StatusCode::INTERNAL_SERVER_ERROR => {
                tracing::error!("Internal server error: {}", error_message);
            }
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                tracing::warn!("{}: {}", error_type, error_message);
            }
            _ => {
                tracing::debug!("{}: {}", error_type, error_message);
            }
        }

        let body = Json(json!({
            "error": {
                "type": error_type,
                "message": error_message,
                "status": status.as_u16()
            }
        }));

        (status, body).into_response()
    }
}

impl From<DbError> for AppError {
    fn from(err: DbError) -> Self {
        AppError::Database(err)
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                AppError::Auth("Your session has expired, please login again".to_string())
            }
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                AppError::Auth("Invalid authentication token".to_string())
            }
            _ => AppError::Auth(format!("Authentication error: {}", err)),
        }
    }
}

impl From<bcrypt::BcryptError> for AppError {
    fn from(err: bcrypt::BcryptError) -> Self {
        AppError::Internal(format!("Password hashing error: {}", err))
    }
}

impl From<crate::auth::utils::token::TokenError> for AppError {
    fn from(err: crate::auth::utils::token::TokenError) -> Self {
        match err {
            crate::auth::utils::token::TokenError::TokenNotFound => {
                AppError::Token("Token not found or invalid".to_string())
            }
            crate::auth::utils::token::TokenError::TokenExpired => {
                AppError::Token("Token has expired".to_string())
            }
            crate::auth::utils::token::TokenError::Database(db_err) => {
                AppError::Database(DbError::Sqlx(db_err))
            }
            crate::auth::utils::token::TokenError::InvalidFormat => {
                AppError::Validation("Invalid token format".to_string())
            }
            crate::auth::utils::token::TokenError::Other(msg) => {
                AppError::Token(format!("Token error: {}", msg))
            }
        }
    }
}
