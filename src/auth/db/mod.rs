//! Database module
//! This module handles database connections and queries

pub mod tokens;
pub mod users;

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

/// Application database error types
#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("Database connection error: {0}")]
    ConnectionError(String),

    #[error("User not found")]
    UserNotFound,

    #[error("Email already exists")]
    EmailExists,
}

/// Result type for database operations
pub type DbResult<T> = Result<T, DbError>;

/// Create a new database connection pool
pub async fn create_pool(database_url: &str) -> DbResult<PgPool> {
    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(database_url)
        .await
        .map_err(|e| DbError::ConnectionError(e.to_string()))
}

/// Initialize the database
/// This function runs migrations and performs any necessary setup
pub async fn initialize(pool: &PgPool) -> DbResult<()> {
    // Run migrations
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| DbError::ConnectionError(format!("Migration failed: {}", e)))?;

    Ok(())
}
