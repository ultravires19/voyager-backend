//! User database operations
//! This module handles all database operations related to users

use sqlx::{postgres::PgPool, query_as, types::time::OffsetDateTime};
use uuid::Uuid;

use crate::{
    auth::db::{DbError, DbResult},
    auth::models::user::{RegisterUser, UserModel},
    auth::utils::{
        password::hash_password,
        token::{generate_password_reset_token, generate_verification_token},
    },
};

/// Create a new user in the database
pub async fn create_user(pool: &PgPool, user_data: &RegisterUser) -> DbResult<UserModel> {
    // Check if email already exists
    let existing = find_by_email(pool, &user_data.email).await;

    if let Ok(_) = existing {
        return Err(DbError::EmailExists);
    }

    // Hash the password
    let password_hash = hash_password(&user_data.password)
        .map_err(|e| DbError::ConnectionError(format!("Password hashing error: {}", e)))?;

    // Generate a new UUID for the user
    let id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    // Insert the new user
    let user = query_as::<_, UserModel>(
        r#"
        INSERT INTO users (id, email, password_hash, email_verified, first_name, last_name, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(&user_data.email)
    .bind(&password_hash)
    .bind(false) // Email not verified by default
    .bind(&user_data.first_name)
    .bind(&user_data.last_name)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(DbError::Sqlx)?;

    Ok(user)
}

/// Find a user by email
pub async fn find_by_email(pool: &PgPool, email: &str) -> DbResult<UserModel> {
    let user = query_as::<_, UserModel>(
        r#"
        SELECT * FROM users WHERE email = $1
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Sqlx)?
    .ok_or(DbError::UserNotFound)?;

    Ok(user)
}

/// Find a user by ID
pub async fn find_by_id(pool: &PgPool, id: &Uuid) -> DbResult<UserModel> {
    let user = query_as::<_, UserModel>(
        r#"
        SELECT * FROM users WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Sqlx)?
    .ok_or(DbError::UserNotFound)?;

    Ok(user)
}

/// Update user's email verification status
#[allow(dead_code)]
pub async fn verify_email(pool: &PgPool, user_id: &Uuid) -> DbResult<UserModel> {
    let user = query_as::<_, UserModel>(
        r#"
        UPDATE users
        SET email_verified = true,
            verification_token = NULL,
            verification_token_expires_at = NULL,
            updated_at = $1
        WHERE id = $2
        RETURNING *
        "#,
    )
    .bind(OffsetDateTime::now_utc())
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Sqlx)?
    .ok_or(DbError::UserNotFound)?;

    Ok(user)
}

/// Update user's password
pub async fn update_password(
    pool: &PgPool,
    user_id: &Uuid,
    password_hash: &str,
) -> DbResult<UserModel> {
    let user = query_as::<_, UserModel>(
        r#"
        UPDATE users
        SET password_hash = $1, updated_at = $2
        WHERE id = $3
        RETURNING *
        "#,
    )
    .bind(password_hash)
    .bind(OffsetDateTime::now_utc())
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Sqlx)?
    .ok_or(DbError::UserNotFound)?;

    Ok(user)
}

/// Find a user by verification token
#[allow(dead_code)]
pub async fn find_by_verification_token(pool: &PgPool, token: &str) -> DbResult<UserModel> {
    let user = query_as::<_, UserModel>(
        r#"
        SELECT * FROM users WHERE verification_token = $1
        "#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Sqlx)?
    .ok_or(DbError::UserNotFound)?;

    Ok(user)
}

/// Find a user by password reset token
#[allow(dead_code)]
pub async fn find_by_reset_token(pool: &PgPool, token: &str) -> DbResult<UserModel> {
    let user = query_as::<_, UserModel>(
        r#"
        SELECT * FROM users WHERE reset_password_token = $1
        "#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Sqlx)?
    .ok_or(DbError::UserNotFound)?;

    Ok(user)
}

/// Create or update email verification token
pub async fn create_verification_token(
    pool: &PgPool,
    user_id: &Uuid,
    expires_hours: i64,
) -> DbResult<String> {
    // Generate the token and store it
    let token = generate_verification_token(pool, user_id, expires_hours)
        .await
        .map_err(|e| DbError::ConnectionError(format!("Token generation error: {}", e)))?;

    Ok(token)
}

/// Create or update password reset token
#[allow(dead_code)]
pub async fn create_reset_token(
    pool: &PgPool,
    user_id: &Uuid,
    expires_hours: i64,
) -> DbResult<String> {
    // Generate the token and store it
    let token = generate_password_reset_token(pool, user_id, expires_hours)
        .await
        .map_err(|e| DbError::ConnectionError(format!("Token generation error: {}", e)))?;

    Ok(token)
}

/// Delete a user by ID
#[allow(dead_code)]
pub async fn delete_user(pool: &PgPool, user_id: &Uuid) -> DbResult<()> {
    let result = sqlx::query(
        r#"
        DELETE FROM users WHERE id = $1
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(DbError::Sqlx)?;

    if result.rows_affected() == 0 {
        return Err(DbError::UserNotFound);
    }

    Ok(())
}
