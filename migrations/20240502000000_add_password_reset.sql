-- Add password reset token fields to users table
ALTER TABLE users
ADD COLUMN reset_password_token VARCHAR(255),
ADD COLUMN reset_password_token_expires_at TIMESTAMPTZ;

-- Create index on reset_password_token for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_reset_password_token ON users(reset_password_token);
