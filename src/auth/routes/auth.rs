//! Authentication routes
//! This module handles all authentication-related endpoints

use axum::http::HeaderMap;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use tower_cookies::cookie::time::Duration;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};

use uuid::Uuid;

use crate::{
    AppState,
    auth::db::{DbError, tokens, users},
    auth::models::user::{
        AuthResponse, LoginCredentials, PasswordResetConfirmation, PasswordResetRequest,
        RegisterUser, ResendVerificationRequest, User,
    },
    auth::services::email::EmailService,
    auth::utils::{
        error::{AppError, Result},
        jwt::generate_token,
        password::{hash_password, validate_password, verify_password},
        token::{
            TokenError, clear_password_reset_token, generate_password_reset_token,
            verify_email_token, verify_password_reset_token,
        },
    },
};

/// Create auth routes
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/verify-email/{token}", get(verify_email))
        .route("/auth/resend-verification", post(resend_verification))
        .route("/auth/refresh", post(refresh_token))
        .route(
            "/auth/validate-reset-token/{token}",
            get(validate_reset_token),
        )
        .route("/auth/forgot-password", post(forgot_password))
        .route("/auth/reset-password", post(reset_password))
        .layer(CookieManagerLayer::new())
}

/// Set refresh token as HTTP-only cookie
fn set_refresh_token_cookie(cookies: &Cookies, refresh_token: &str) {
    let mut cookie = Cookie::new("refresh_token", refresh_token.to_string());

    cookie.set_http_only(true);
    cookie.set_secure(true); // only send over HTTPS
    cookie.set_max_age(Duration::days(30));
    cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    cookie.set_path("/");

    cookies.add(cookie);
}

/// Extract refresh token from cookie
fn get_refresh_token_cookie(cookies: &Cookies) -> Result<String> {
    cookies
        .get("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| AppError::Auth("Missing refresh token".to_string()))
}

/// Clear refresh token cookie for logout
fn clear_refresh_token_cookie(cookies: &Cookies) {
    cookies.remove(Cookie::new("refresh_token", ""));
}

/// Register a new user
async fn register(
    cookies: Cookies,
    State(state): State<AppState>,
    Json(input): Json<RegisterUser>,
) -> Result<Json<AuthResponse>> {
    // Validate email format (simple validation, enhance as needed)
    if !input.email.contains('@') {
        return Err(AppError::Validation("Invalid email format".to_string()));
    }

    // Validate password strength
    validate_password(&input.password)?;

    // Create user in database
    let user = users::create_user(&state.pool, &input).await?;

    // Generate verification token (valid for 24 hours)
    let verification_token = users::create_verification_token(&state.pool, &user.id, 24).await?;

    // Build verification URL
    let base_url =
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:5173".to_string());
    let verification_url = format!("{}/verify-email/{}", base_url, verification_token);

    // Get user's name for the email
    let user_name = match (&user.first_name, &user.last_name) {
        (Some(first), Some(last)) => Some(format!("{} {}", first, last)),
        (Some(first), None) => Some(first.clone()),
        (None, Some(last)) => Some(last.clone()),
        (None, None) => None,
    };

    // Send verification email
    match state
        .email_service
        .send_verification_email(&user.email, &verification_url, user_name.as_deref())
        .await
    {
        Ok(_) => {
            tracing::info!("Verification email sent successfully to {}", user.email)
        }
        Err(e) => {
            tracing::error!("Failed to send verification email to {}: {}", user.email, e)
        }
    }

    // Generate JWT access token
    let token = generate_token(&user.id.to_string(), &user.email)
        .map_err(|e| AppError::Internal(format!("Failed to generate token: {}", e)))?;

    // Generate refresh token (valid for 30 days)
    let refresh_token = tokens::create_refresh_token(&state.pool, &user.id, 30 * 24)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create refresh token: {}", e)))?;

    // Set refresh token as HTTP-only cookie
    set_refresh_token_cookie(&cookies, &refresh_token);

    // Convert to user response
    let user_response = User::from(user);

    // Return user data and tokens
    Ok(Json(AuthResponse {
        user: user_response,
        token,
    }))
}

/// Login an existing user
async fn login(
    cookies: Cookies,
    State(state): State<AppState>,
    Json(credentials): Json<LoginCredentials>,
) -> Result<Json<AuthResponse>> {
    // Find user by email
    let user = users::find_by_email(&state.pool, &credentials.email)
        .await
        .map_err(|_| AppError::Auth("Invalid email or password".to_string()))?;

    // Verify password
    let is_valid = verify_password(&credentials.password, &user.password_hash)?;

    if !is_valid {
        return Err(AppError::Auth("Invalid email or password".to_string()));
    }

    // Generate JWT access token
    let token = generate_token(&user.id.to_string(), &user.email)
        .map_err(|e| AppError::Internal(format!("Failed to generate token: {}", e)))?;

    // Generate refresh token (valid for 30 days)
    let refresh_token = tokens::create_refresh_token(&state.pool, &user.id, 30 * 24)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create refresh token: {}", e)))?;

    set_refresh_token_cookie(&cookies, &refresh_token);

    // Convert to user response
    let user_response = User::from(user);

    // Return user data and tokens
    Ok(Json(AuthResponse {
        user: user_response,
        token,
    }))
}

/// Verify email address
async fn verify_email(
    State(state): State<AppState>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Result<Json<User>> {
    // Verify the token and update the user's email_verified status
    let result = verify_email_token(&state.pool, &token).await;

    match result {
        Ok(user) => {
            // Return the updated user
            Ok(Json(User::from(user)))
        }
        Err(TokenError::TokenExpired) => {
            Err(AppError::Auth("Verification token has expired".to_string()))
        }
        Err(TokenError::TokenNotFound) => {
            Err(AppError::NotFound("Invalid verification token".to_string()))
        }
        Err(e) => {
            tracing::error!("Error verifying email token: {}", e);
            Err(AppError::Internal("Failed to verify email".to_string()))
        }
    }
}

/// Resend verification email
async fn resend_verification(
    State(state): State<AppState>,
    Json(input): Json<ResendVerificationRequest>,
) -> Result<Json<()>> {
    // Find the user by email
    let user = users::find_by_email(&state.pool, &input.email)
        .await
        .map_err(|_| AppError::NotFound("User not found".to_string()))?;

    // Check if already verified
    if user.email_verified {
        return Err(AppError::Validation("Email already verified".to_string()));
    }

    // Generate new verification token (valid for 24 hours)
    let verification_token = users::create_verification_token(&state.pool, &user.id, 24).await?;

    // Build verification URL
    let base_url =
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:5173".to_string());
    let verification_url = format!("{}/verify-email/{}", base_url, verification_token);

    // Get user's name for the email
    let user_name = match (&user.first_name, &user.last_name) {
        (Some(first), Some(last)) => Some(format!("{} {}", first, last)),
        (Some(first), None) => Some(first.clone()),
        (None, Some(last)) => Some(last.clone()),
        (None, None) => None,
    };

    // Send verification email
    state
        .email_service
        .send_verification_email(&user.email, &verification_url, user_name.as_deref())
        .await
        .map_err(|e| {
            tracing::error!("Failed to send verification email: {}", e);
            AppError::Internal("Failed to send verification email".to_string())
        })?;

    Ok(Json(()))
}

/// Refresh authentication token
#[axum::debug_handler]
async fn refresh_token(
    State(state): State<AppState>,
    cookies: Cookies, // ← Add this
) -> Result<Json<AuthResponse>> {
    // Extract refresh token from cookie
    let refresh_token = get_refresh_token_cookie(&cookies)?;

    // Validate the refresh token
    let user_id = tokens::validate_refresh_token(&state.pool, &refresh_token)
        .await
        .map_err(|e| match e {
            DbError::ConnectionError(msg) if msg.contains("refresh token") => {
                AppError::Token("Invalid or expired refresh token".to_string())
            }
            _ => AppError::Database(e),
        })?;

    // Get the user
    let user = users::find_by_id(&state.pool, &user_id)
        .await
        .map_err(|e| match e {
            DbError::UserNotFound => {
                AppError::NotFound("User account no longer exists".to_string())
            }
            _ => AppError::Database(e),
        })?;

    // Generate a new access token
    let token = generate_token(&user.id.to_string(), &user.email)
        .map_err(|e| AppError::Internal(format!("Failed to generate token: {}", e)))?;

    // Generate a new refresh token and revoke the old one (rotation)
    let new_refresh_token = tokens::create_refresh_token(&state.pool, &user.id, 30 * 24)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create refresh token: {}", e)))?;

    // Set new refresh token as HTTP-only cookie
    set_refresh_token_cookie(&cookies, &new_refresh_token);

    // Convert to user response
    let user_response = User::from(user);

    // Return user data and new access token (new refresh token is in cookie)
    Ok(Json(AuthResponse {
        user: user_response,
        token,
    }))
}

/// Logout and revoke refresh token
#[axum::debug_handler]
async fn logout(
    cookies: Cookies,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<()>> {
    clear_refresh_token_cookie(&cookies);

    // Extract refresh token if still present
    if let Ok(refresh_token) = get_refresh_token_cookie(&cookies) {
        if let Err(e) = tokens::revoke_refresh_token(&state.pool, &refresh_token).await {
            tracing::warn!("Failed to revoke refresh token: {}", e);
        }
    }

    // Extract and revoke all user tokens from JWT
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(header_str) = auth_header.to_str() {
            if let Some(token) = header_str.strip_prefix("Bearer ") {
                if let Ok(claims) = crate::auth::utils::jwt::verify_token(token) {
                    if let Ok(user_id) = Uuid::parse_str(&claims.sub) {
                        if let Err(e) = tokens::revoke_user_tokens(&state.pool, &user_id).await {
                            tracing::warn!("Failed to revoke user tokens: {}", e);
                        }
                    }
                }
            }
        }
    }

    // Return success - frontend will clear token from storage
    Ok(Json(()))
}

/// Request a password reset
async fn forgot_password(
    State(state): State<AppState>,
    Json(input): Json<PasswordResetRequest>,
) -> Result<Json<()>> {
    // Validate email format
    if !input.email.contains('@') {
        return Err(AppError::Validation("Invalid email format".to_string()));
    }

    // Find user by email
    let user = match users::find_by_email(&state.pool, &input.email).await {
        Ok(user) => user,
        Err(_) => {
            // Don't reveal if the email exists or not for security reasons
            // Just return success as if we sent the email
            return Ok(Json(()));
        }
    };

    // Generate reset token (valid for 1 hour)
    let reset_token = generate_password_reset_token(&state.pool, &user.id, 1)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to generate reset token: {}", e)))?;

    // Build reset URL
    let base_url =
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:5173".to_string());
    let reset_url = format!("{}/reset-password/{}", base_url, reset_token);

    // Get user's name for the email
    let user_name = match (&user.first_name, &user.last_name) {
        (Some(first), Some(last)) => Some(format!("{} {}", first, last)),
        (Some(first), None) => Some(first.clone()),
        (None, Some(last)) => Some(last.clone()),
        (None, None) => None,
    };

    // Send password reset email
    state
        .email_service
        .send_password_reset_email(&user.email, &reset_url, user_name.as_deref())
        .await
        .map_err(|e| {
            tracing::error!("Failed to send password reset email: {}", e);
            AppError::Internal("Failed to send password reset email".to_string())
        })?;

    Ok(Json(()))
}

/// Validate a password reset token
async fn validate_reset_token(
    State(state): State<AppState>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Result<Json<()>> {
    // Verify the token is valid
    match verify_password_reset_token(&state.pool, &token).await {
        Ok(_) => Ok(Json(())),
        Err(TokenError::TokenExpired) => {
            Err(AppError::Token("Reset token has expired".to_string()))
        }
        Err(TokenError::TokenNotFound) => {
            Err(AppError::NotFound("Invalid reset token".to_string()))
        }
        Err(e) => {
            tracing::error!("Error validating reset token: {}", e);
            Err(AppError::Internal(
                "Failed to validate reset token".to_string(),
            ))
        }
    }
}

/// Reset password with token
async fn reset_password(
    State(state): State<AppState>,
    Json(input): Json<PasswordResetConfirmation>,
) -> Result<Json<()>> {
    // Validate password strength
    validate_password(&input.new_password)?;

    // Verify the token
    let user = verify_password_reset_token(&state.pool, &input.token)
        .await
        .map_err(|e| match e {
            TokenError::TokenExpired => AppError::Token("Reset token has expired".to_string()),
            TokenError::TokenNotFound => AppError::NotFound("Invalid reset token".to_string()),
            _ => AppError::Internal("Failed to verify reset token".to_string()),
        })?;

    // Hash the new password
    let password_hash = hash_password(&input.new_password)
        .map_err(|e| AppError::Internal(format!("Password hashing error: {}", e)))?;

    // Update the user's password
    users::update_password(&state.pool, &user.id, &password_hash)
        .await
        .map_err(|e| AppError::Database(e))?;

    // Clear the reset token
    clear_password_reset_token(&state.pool, &user.id)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to clear reset token: {}", e)))?;

    // Return success
    Ok(Json(()))
}
