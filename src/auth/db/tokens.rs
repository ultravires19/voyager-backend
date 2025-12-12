//! Token database operations
//! This module handles database operations for tokens (refresh, reset, etc.)

use sqlx::{postgres::PgPool, query_as, types::time::OffsetDateTime};
use std::time::Duration;
use uuid::Uuid;

use crate::{
    auth::db::{DbError, DbResult},
    auth::models::user::RefreshTokenModel,
    auth::utils::token::{generate_secure_token, hash_token},
};

/// Create a new refresh token for a user
pub async fn create_refresh_token(
    pool: &PgPool,
    user_id: &Uuid,
    expires_hours: i64,
) -> DbResult<String> {
    // Revoke any existing refresh tokens for this user
    // This is optional and depends on your token strategy (single token vs multiple tokens)
    if let Err(e) = revoke_user_tokens(pool, user_id).await {
        tracing::warn!(
            "Failed to revoke previous tokens for user {}: {}",
            user_id,
            e
        );
        // Continue execution even if revocation fails
    }

    // Generate a secure token
    let token = generate_secure_token();

    // Hash the token for storage
    // We store the hash, but return the original to the client
    let token_hash = hash_token(&token)
        .map_err(|e| DbError::ConnectionError(format!("Token hashing error: {}", e)))?;

    // Calculate expiration time
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::from_secs((expires_hours * 60 * 60) as u64);

    // Generate a new UUID for the token
    let id = Uuid::new_v4();

    // Insert the new token
    query_as::<_, RefreshTokenModel>(
        r#"
        INSERT INTO refresh_tokens (id, user_id, token, expires_at, created_at, revoked)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(now)
    .bind(false)
    .fetch_one(pool)
    .await
    .map_err(|e| DbError::Sqlx(e))?;

    // Return the original token (not the hash)
    Ok(token)
}

/// Validate a refresh token and return the user ID if valid
pub async fn validate_refresh_token(pool: &PgPool, token: &str) -> DbResult<Uuid> {
    // Hash the token for comparison
    let token_hash = hash_token(token)
        .map_err(|e| DbError::ConnectionError(format!("Token hashing error: {}", e)))?;

    // Find the token in the database
    let refresh_token = query_as::<_, RefreshTokenModel>(
        r#"
        SELECT * FROM refresh_tokens
        WHERE token = $1 AND revoked = false AND expires_at > $2
        "#,
    )
    .bind(&token_hash)
    .bind(OffsetDateTime::now_utc())
    .fetch_optional(pool)
    .await
    .map_err(DbError::Sqlx)?
    .ok_or(DbError::ConnectionError(
        "Invalid or expired refresh token. Please log in again.".to_string(),
    ))?;

    // Return the user ID
    Ok(refresh_token.user_id)
}

/// Revoke a specific refresh token
pub async fn revoke_refresh_token(pool: &PgPool, token: &str) -> DbResult<()> {
    // Hash the token for comparison
    let token_hash = hash_token(token)
        .map_err(|e| DbError::ConnectionError(format!("Token hashing error: {}", e)))?;

    // Mark the token as revoked
    let result = sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked = true
        WHERE token = $1
        "#,
    )
    .bind(&token_hash)
    .execute(pool)
    .await
    .map_err(|e| DbError::Sqlx(e))?;

    if result.rows_affected() == 0 {
        return Err(DbError::ConnectionError(
            "Token not found or already revoked".to_string(),
        ));
    }

    Ok(())
}

/// Revoke all refresh tokens for a user
pub async fn revoke_user_tokens(pool: &PgPool, user_id: &Uuid) -> DbResult<()> {
    // Mark all tokens for this user as revoked
    sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked = true
        WHERE user_id = $1 AND revoked = false
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|e| DbError::Sqlx(e))?;

    Ok(())
}

/// Clean up expired tokens (can be run periodically)
#[allow(dead_code)]
pub async fn clean_expired_tokens(pool: &PgPool) -> DbResult<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM refresh_tokens
        WHERE expires_at < $1
        "#,
    )
    .bind(OffsetDateTime::now_utc())
    .execute(pool)
    .await
    .map_err(|e| DbError::Sqlx(e))?;

    Ok(result.rows_affected())
}
