//! Token utilities
//! This module provides utilities for generating and validating tokens

use chrono::{Duration, Utc};
use rand::{Rng, distributions::Alphanumeric};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPool, query_as, types::time::OffsetDateTime};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::models::user::UserModel;

/// Token error
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token not found")]
    TokenNotFound,

    #[error("Token expired")]
    TokenExpired,

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Invalid token format")]
    InvalidFormat,

    #[error("Other error: {0}")]
    Other(String),
}

pub type TokenResult<T> = Result<T, TokenError>;

/// Generate a random token
pub fn generate_token(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Generate a secure token for refresh tokens
pub fn generate_secure_token() -> String {
    // Generate a longer token for security
    generate_token(64)
}

/// Hash a token for secure storage
pub fn hash_token(token: &str) -> Result<String, TokenError> {
    // Create a SHA-256 hasher
    let mut hasher = Sha256::new();

    // Update hasher with token bytes
    hasher.update(token.as_bytes());

    // Get the hash result
    let result = hasher.finalize();

    // Convert to hex string
    let hash = format!("{:x}", result);

    Ok(hash)
}

/// Generate an email verification token and set expiration
pub async fn generate_verification_token(
    pool: &PgPool,
    user_id: &Uuid,
    expires_in_hours: i64,
) -> TokenResult<String> {
    // Generate a random token
    let token = generate_token(32);

    // Calculate expiration time
    let now = Utc::now();
    let expires_at = now + Duration::hours(expires_in_hours);
    let expires_at = OffsetDateTime::from_unix_timestamp(expires_at.timestamp()).unwrap();

    // Store token in the database
    query_as::<_, UserModel>(
        r#"
        UPDATE users
        SET verification_token = $1, verification_token_expires_at = $2, updated_at = $3
        WHERE id = $4
        RETURNING *
        "#,
    )
    .bind(&token)
    .bind(expires_at)
    .bind(OffsetDateTime::now_utc())
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(TokenError::Database)?;

    Ok(token)
}

/// Verify an email verification token
pub async fn verify_email_token(pool: &PgPool, token: &str) -> TokenResult<UserModel> {
    // Find user with this token
    let user = query_as::<_, UserModel>(
        r#"
        SELECT * FROM users WHERE verification_token = $1
        "#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .map_err(TokenError::Database)?
    .ok_or(TokenError::TokenNotFound)?;

    // Check if token is expired
    if let Some(expires_at) = user.verification_token_expires_at {
        let now = OffsetDateTime::now_utc();
        if now > expires_at {
            return Err(TokenError::TokenExpired);
        }
    } else {
        return Err(TokenError::TokenExpired);
    }

    // Mark email as verified and clear token
    let verified_user = query_as::<_, UserModel>(
        r#"
        UPDATE users
        SET email_verified = true, verification_token = NULL,
            verification_token_expires_at = NULL, updated_at = $1
        WHERE id = $2
        RETURNING *
        "#,
    )
    .bind(OffsetDateTime::now_utc())
    .bind(user.id)
    .fetch_one(pool)
    .await
    .map_err(TokenError::Database)?;

    Ok(verified_user)
}

/// Generate a password reset token and set expiration
pub async fn generate_password_reset_token(
    pool: &PgPool,
    user_id: &Uuid,
    expires_in_hours: i64,
) -> TokenResult<String> {
    // Generate a random token
    let token = generate_token(32);

    // Calculate expiration time
    let now = Utc::now();
    let expires_at = now + Duration::hours(expires_in_hours);
    let expires_at = OffsetDateTime::from_unix_timestamp(expires_at.timestamp()).unwrap();

    // Store token in the database
    query_as::<_, UserModel>(
        r#"
        UPDATE users
        SET reset_password_token = $1, reset_password_token_expires_at = $2, updated_at = $3
        WHERE id = $4
        RETURNING *
        "#,
    )
    .bind(&token)
    .bind(expires_at)
    .bind(OffsetDateTime::now_utc())
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(TokenError::Database)?;

    Ok(token)
}

/// Verify a password reset token
pub async fn verify_password_reset_token(pool: &PgPool, token: &str) -> TokenResult<UserModel> {
    // Find user with this token
    let user = query_as::<_, UserModel>(
        r#"
        SELECT * FROM users WHERE reset_password_token = $1
        "#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .map_err(TokenError::Database)?
    .ok_or(TokenError::TokenNotFound)?;

    // Check if token is expired
    if let Some(expires_at) = user.reset_password_token_expires_at {
        let now = OffsetDateTime::now_utc();
        if now > expires_at {
            return Err(TokenError::TokenExpired);
        }
    } else {
        return Err(TokenError::TokenExpired);
    }

    Ok(user)
}

/// Clear a password reset token after use
pub async fn clear_password_reset_token(pool: &PgPool, user_id: &Uuid) -> TokenResult<UserModel> {
    // Clear the token
    let user = query_as::<_, UserModel>(
        r#"
        UPDATE users
        SET reset_password_token = NULL, reset_password_token_expires_at = NULL, updated_at = $1
        WHERE id = $2
        RETURNING *
        "#,
    )
    .bind(OffsetDateTime::now_utc())
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(TokenError::Database)?;

    Ok(user)
}
