//! JWT utilities
//! This module handles JWT token generation and validation

use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

use crate::auth::utils::error::{AppError, Result};

/// JWT error types
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Missing token")]
    MissingToken,

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("Environment error: {0}")]
    EnvError(String),
}

/// JWT claims structure for token payload
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Token ID
    pub jti: String,
    /// User email
    pub email: String,
}

/// Default token expiration time in seconds (24 hours)
const DEFAULT_EXP_SECONDS: i64 = 86400;

/// Get JWT secret from environment
fn get_jwt_secret() -> std::result::Result<String, JwtError> {
    // In production, this should come from an environment variable
    // For development, we'll use a default secret
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
        // Log a warning when using default secret in production
        if env::var("RUST_ENV").unwrap_or_else(|_| "development".to_string()) == "production" {
            tracing::warn!("Using default JWT secret in production environment!");
        }
        "your-jwt-secret-key-change-in-production".to_string()
    });
    Ok(secret)
}

/// Generate a new JWT token for a user
pub fn generate_token(user_id: &str, email: &str) -> Result<String> {
    let secret =
        get_jwt_secret().map_err(|e| AppError::Internal(format!("JWT secret error: {}", e)))?;

    let now = Utc::now();
    let expires_at = now + Duration::seconds(DEFAULT_EXP_SECONDS);

    let claims = Claims {
        sub: user_id.to_string(),
        iat: now.timestamp(),
        exp: expires_at.timestamp(),
        jti: Uuid::new_v4().to_string(),
        email: email.to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::InvalidToken => {
            AppError::Auth("Invalid token format".to_string())
        }
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            AppError::Auth("Token expired".to_string())
        }
        _ => AppError::Internal(format!("Failed to generate token: {}", e)),
    })
}

/// Validate a JWT token and extract the claims
pub fn validate_token(token: &str) -> Result<Claims> {
    let secret =
        get_jwt_secret().map_err(|e| AppError::Internal(format!("JWT secret error: {}", e)))?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            AppError::Token("Token has expired".to_string())
        }
        jsonwebtoken::errors::ErrorKind::InvalidToken => {
            AppError::Token("Invalid token format".to_string())
        }
        jsonwebtoken::errors::ErrorKind::InvalidSignature => {
            AppError::Token("Invalid token signature".to_string())
        }
        _ => AppError::Auth(format!("Token validation error: {}", e)),
    })?;

    Ok(token_data.claims)
}

/// Extract token from Authorization header
pub fn extract_token(auth_header: Option<String>) -> Result<String> {
    match auth_header {
        Some(header) if header.starts_with("Bearer ") => Ok(header[7..].to_string()),
        Some(_) => Err(AppError::Auth(
            "Invalid authorization format. Expected 'Bearer <token>'".to_string(),
        )),
        None => Err(AppError::Auth("Missing authorization header".to_string())),
    }
}

/// Check if a token is expired
pub fn is_token_expired(exp: i64) -> bool {
    let now = Utc::now().timestamp();
    exp < now
}

/// Verify and decode a token - returns JwtError directly for better error handling
pub fn verify_token(token: &str) -> std::result::Result<Claims, JwtError> {
    let secret = get_jwt_secret()?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;

    // Additional check for expiration
    if is_token_expired(token_data.claims.exp) {
        return Err(JwtError::TokenExpired);
    }

    Ok(token_data.claims)
}
