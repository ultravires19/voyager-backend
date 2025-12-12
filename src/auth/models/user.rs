//! User model
//! This module contains the User model and related types

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, types::time::OffsetDateTime};
use uuid::Uuid;

/// Database user model
/// This model maps directly to the users table in the database
#[derive(Debug, Clone, FromRow)]
pub struct UserModel {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub verification_token: Option<String>,
    pub verification_token_expires_at: Option<OffsetDateTime>,
    pub reset_password_token: Option<String>,
    pub reset_password_token_expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// User data sent to clients
/// This is a subset of user data that's safe to send to clients
/// (excludes password hash and other sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// New user registration data
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegisterUser {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// User login credentials
#[derive(Debug, Clone, Deserialize)]
pub struct LoginCredentials {
    pub email: String,
    pub password: String,
}

/// Email verification request payload
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

/// Resend verification email request
#[derive(Debug, Clone, Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

/// Refresh token request payload
// #[derive(Debug, Clone, Deserialize)]
// pub struct RefreshTokenRequest {
//     pub refresh_token: String,
// }

/// Logout request payload
#[derive(Debug, Clone, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: Option<String>,
}

/// Password reset request payload
#[derive(Debug, Clone, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

/// Password reset confirmation payload
#[derive(Debug, Clone, Deserialize)]
pub struct PasswordResetConfirmation {
    pub token: String,
    pub new_password: String,
}

/// Refresh token database model
#[derive(Debug, Clone, FromRow)]
pub struct RefreshTokenModel {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub revoked: bool,
}

/// Authentication response containing user and token
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: User,
    pub token: String,
    // pub refresh_token: Option<String>,
}

impl From<UserModel> for User {
    fn from(model: UserModel) -> Self {
        Self {
            id: model.id.to_string(),
            email: model.email,
            email_verified: model.email_verified,
            first_name: model.first_name,
            last_name: model.last_name,
            created_at: Utc
                .timestamp_opt(model.created_at.unix_timestamp(), 0)
                .unwrap(),
        }
    }
}
