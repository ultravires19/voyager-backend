//! Password utilities
//! This module handles password hashing and verification

use bcrypt::{DEFAULT_COST, hash, verify};

use crate::auth::utils::error::{AppError, Result};

/// Hash a password using bcrypt
///
/// # Arguments
/// * `password` - The plain text password to hash
///
/// # Returns
/// * `Result<String>` - The hashed password or an error
pub fn hash_password(password: &str) -> Result<String> {
    hash(password, DEFAULT_COST)
        .map_err(|e| AppError::Internal(format!("Failed to hash password: {}", e)))
}

/// Verify a password against a hash
///
/// # Arguments
/// * `password` - The plain text password to verify
/// * `hash` - The password hash to verify against
///
/// # Returns
/// * `Result<bool>` - True if the password matches, false otherwise
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    verify(password, hash)
        .map_err(|e| AppError::Internal(format!("Failed to verify password: {}", e)))
}

/// Validate password strength
///
/// # Arguments
/// * `password` - The password to validate
///
/// # Returns
/// * `Result<()>` - Ok if the password is valid, Err with message otherwise
pub fn validate_password(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(AppError::Validation(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    if !password.chars().any(|c| c.is_ascii_alphabetic()) {
        return Err(AppError::Validation(
            "Password must contain at least one letter".to_string(),
        ));
    }

    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AppError::Validation(
            "Password must contain at least one number".to_string(),
        ));
    }

    Ok(())
}
