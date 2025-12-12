//! Email service
//! This module provides functionality for sending emails

use chrono::Datelike;
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmailError {
    #[error("Failed to send email: {0}")]
    SendError(String),

    #[error("Failed to serialize email: {0}")]
    SerializationError(String),

    #[error("Error creating HTTP request: {0}")]
    RequestError(String),

    #[error("Missing configuration: {0}")]
    ConfigError(String),
}

pub type EmailResult<T> = Result<T, EmailError>;

/// Email service trait
/// This trait defines the interface for email services
pub trait EmailService {
    /// Send an email
    async fn send_email(&self, email: Email) -> EmailResult<()>;

    /// Send a verification email to a user
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_url: &str,
        user_name: Option<&str>,
    ) -> EmailResult<()>;

    /// Send a password reset email to a user
    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_url: &str,
        user_name: Option<&str>,
    ) -> EmailResult<()>;
}

/// EmailServiceImpl enum to replace dynamic dispatch with static dispatch
#[derive(Clone)]
pub enum EmailServiceImpl {
    SendGrid(SendGridEmailService),
    Resend(ResendEmailService),
    Mock(MockEmailService),
}

impl EmailService for EmailServiceImpl {
    async fn send_email(&self, email: Email) -> EmailResult<()> {
        match self {
            Self::SendGrid(service) => service.send_email(email).await,
            Self::Resend(service) => service.send_email(email).await,
            Self::Mock(service) => service.send_email(email).await,
        }
    }

    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_url: &str,
        user_name: Option<&str>,
    ) -> EmailResult<()> {
        match self {
            Self::SendGrid(service) => {
                service
                    .send_verification_email(to_email, verification_url, user_name)
                    .await
            }
            Self::Resend(service) => {
                service
                    .send_verification_email(to_email, verification_url, user_name)
                    .await
            }
            Self::Mock(service) => {
                service
                    .send_verification_email(to_email, verification_url, user_name)
                    .await
            }
        }
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_url: &str,
        user_name: Option<&str>,
    ) -> EmailResult<()> {
        match self {
            Self::SendGrid(service) => {
                service
                    .send_password_reset_email(to_email, reset_url, user_name)
                    .await
            }
            Self::Resend(service) => {
                service
                    .send_password_reset_email(to_email, reset_url, user_name)
                    .await
            }
            Self::Mock(service) => {
                service
                    .send_password_reset_email(to_email, reset_url, user_name)
                    .await
            }
        }
    }
}

/// Email structure for sending messages
#[derive(Debug, Clone, Serialize)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub html_content: String,
    pub text_content: String,
}

/// SendGrid email service implementation
#[derive(Clone)]
pub struct SendGridEmailService {
    api_key: String,
    from_email: String,
    from_name: String,
    client: reqwest::Client,
}

impl SendGridEmailService {
    /// Create a new SendGrid email service
    pub fn new(api_key: String, from_email: String, from_name: String) -> Self {
        Self {
            api_key,
            from_email,
            from_name,
            client: reqwest::Client::new(),
        }
    }

    /// Create a SendGrid JSON payload from an Email
    fn create_sendgrid_payload(&self, email: &Email) -> EmailResult<Value> {
        let payload = json!({
            "personalizations": [
                {
                    "to": [
                        {
                            "email": email.to
                        }
                    ],
                    "subject": email.subject
                }
            ],
            "from": {
                "email": self.from_email,
                "name": self.from_name
            },
            "content": [
                {
                    "type": "text/plain",
                    "value": email.text_content
                },
                {
                    "type": "text/html",
                    "value": email.html_content
                }
            ]
        });

        Ok(payload)
    }
}

impl EmailService for SendGridEmailService {
    async fn send_email(&self, email: Email) -> EmailResult<()> {
        // Create the payload
        let payload = self.create_sendgrid_payload(&email)?;

        // Make the API request
        let response = self
            .client
            .post("https://api.sendgrid.com/v3/mail/send")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| EmailError::RequestError(e.to_string()))?;

        // Check for success
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(EmailError::SendError(format!(
                "SendGrid API error: {} - {}",
                status, error_text
            )));
        }

        Ok(())
    }

    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_url: &str,
        user_name: Option<&str>,
    ) -> EmailResult<()> {
        let greeting = if let Some(name) = user_name {
            format!("Hello, {}!", name)
        } else {
            "Hello!".to_string()
        };

        let html_content = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Verify Your Email Address</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .container {{ border: 1px solid #e0e0e0; border-radius: 5px; padding: 20px; }}
                    .header {{ text-align: center; margin-bottom: 20px; }}
                    .logo {{ font-size: 24px; font-weight: bold; color: #4a6cf7; }}
                    .button {{ display: inline-block; background-color: #4a6cf7; color: white; text-decoration: none; padding: 12px 24px; border-radius: 4px; font-weight: bold; margin: 20px 0; }}
                    .footer {{ margin-top: 30px; font-size: 12px; color: #888; text-align: center; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">AxeBase</div>
                    </div>
                    <p>{}</p>
                    <p>Thank you for signing up. Please verify your email address to complete your registration.</p>
                    <p style="text-align: center;">
                        <a href="{}" class="button">Verify Email Address</a>
                    </p>
                    <p>Or copy and paste the following link into your browser:</p>
                    <p>{}</p>
                    <p>This link will expire in 24 hours.</p>
                    <p>If you didn't create an account, you can safely ignore this email.</p>
                    <div class="footer">
                        <p>&copy; {} AxeBase. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            "#,
            greeting,
            verification_url,
            verification_url,
            chrono::Utc::now().year()
        );

        let text_content = format!(
            r#"
            {}

            Thank you for signing up. Please verify your email address to complete your registration.

            Please visit this link to verify your email address:
            {}

            This link will expire in 24 hours.

            If you didn't create an account, you can safely ignore this email.

            © {} AxeBase. All rights reserved.
            "#,
            greeting,
            verification_url,
            chrono::Utc::now().year()
        );

        let email = Email {
            to: to_email.to_string(),
            subject: "Verify Your Email Address".to_string(),
            html_content,
            text_content,
        };

        self.send_email(email).await
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_url: &str,
        user_name: Option<&str>,
    ) -> EmailResult<()> {
        let greeting = if let Some(name) = user_name {
            format!("Hello, {}!", name)
        } else {
            "Hello!".to_string()
        };

        let html_content = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Reset Your Password</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .container {{ border: 1px solid #e0e0e0; border-radius: 5px; padding: 20px; }}
                    .header {{ text-align: center; margin-bottom: 20px; }}
                    .logo {{ font-size: 24px; font-weight: bold; color: #4a6cf7; }}
                    .button {{ display: inline-block; background-color: #4a6cf7; color: white; text-decoration: none; padding: 12px 24px; border-radius: 4px; font-weight: bold; margin: 20px 0; }}
                    .footer {{ margin-top: 30px; font-size: 12px; color: #888; text-align: center; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">AxeBase</div>
                    </div>
                    <p>{}</p>
                    <p>We received a request to reset your password. Click the button below to create a new password:</p>
                    <p style="text-align: center;">
                        <a href="{}" class="button">Reset Password</a>
                    </p>
                    <p>Or copy and paste the following link into your browser:</p>
                    <p>{}</p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request a password reset, you can safely ignore this email.</p>
                    <div class="footer">
                        <p>&copy; {} AxeBase. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            "#,
            greeting,
            reset_url,
            reset_url,
            chrono::Utc::now().year()
        );

        let text_content = format!(
            r#"
            {}

            We received a request to reset your password. Please use the following link to create a new password:

            {}

            This link will expire in 1 hour.

            If you didn't request a password reset, you can safely ignore this email.

            © {} AxeBase. All rights reserved.
            "#,
            greeting,
            reset_url,
            chrono::Utc::now().year()
        );

        let email = Email {
            to: to_email.to_string(),
            subject: "Reset Your Password".to_string(),
            html_content,
            text_content,
        };

        self.send_email(email).await
    }
}

/// Resend email service implementation using official resend-rs SDK
#[derive(Clone)]
pub struct ResendEmailService {
    client: resend_rs::Resend,
    from_email: String,
    from_name: String,
}

impl ResendEmailService {
    /// Create a new Resend email service
    pub fn new(api_key: String, from_email: String, from_name: String) -> Self {
        Self {
            client: resend_rs::Resend::new(&api_key),
            from_email,
            from_name,
        }
    }
}

impl EmailService for ResendEmailService {
    async fn send_email(&self, email: Email) -> EmailResult<()> {
        use resend_rs::types::CreateEmailBaseOptions;

        let from = format!("{} <{}>", self.from_name, self.from_email);
        let to = vec![email.to.as_str()];

        let email_request = CreateEmailBaseOptions::new(&from, to, &email.subject)
            .with_html(&email.html_content)
            .with_text(&email.text_content);

        self.client
            .emails
            .send(email_request)
            .await
            .map_err(|e| EmailError::SendError(format!("Resend error: {}", e)))?;

        Ok(())
    }

    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_url: &str,
        user_name: Option<&str>,
    ) -> EmailResult<()> {
        let greeting = if let Some(name) = user_name {
            format!("Hello, {}!", name)
        } else {
            "Hello!".to_string()
        };

        let html_content = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Verify Your Email Address</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .container {{ border: 1px solid #e0e0e0; border-radius: 5px; padding: 20px; }}
                    .header {{ text-align: center; margin-bottom: 20px; }}
                    .logo {{ font-size: 24px; font-weight: bold; color: #4a6cf7; }}
                    .button {{ display: inline-block; background-color: #4a6cf7; color: white; text-decoration: none; padding: 12px 24px; border-radius: 4px; font-weight: bold; margin: 20px 0; }}
                    .footer {{ margin-top: 30px; font-size: 12px; color: #888; text-align: center; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">AxeBase</div>
                    </div>
                    <p>{}</p>
                    <p>Thank you for signing up. Please verify your email address to complete your registration.</p>
                    <p style="text-align: center;">
                        <a href="{}" class="button">Verify Email Address</a>
                    </p>
                    <p>Or copy and paste the following link into your browser:</p>
                    <p>{}</p>
                    <p>This link will expire in 24 hours.</p>
                    <p>If you didn't create an account, you can safely ignore this email.</p>
                    <div class="footer">
                        <p>&copy; {} AxeBase. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            "#,
            greeting,
            verification_url,
            verification_url,
            chrono::Utc::now().year()
        );

        let text_content = format!(
            r#"
            {}

            Thank you for signing up. Please verify your email address to complete your registration.

            Please visit this link to verify your email address:
            {}

            This link will expire in 24 hours.

            If you didn't create an account, you can safely ignore this email.

            © {} AxeBase. All rights reserved.
            "#,
            greeting,
            verification_url,
            chrono::Utc::now().year()
        );

        let email = Email {
            to: to_email.to_string(),
            subject: "Verify Your Email Address".to_string(),
            html_content,
            text_content,
        };

        self.send_email(email).await
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_url: &str,
        user_name: Option<&str>,
    ) -> EmailResult<()> {
        let greeting = if let Some(name) = user_name {
            format!("Hello, {}!", name)
        } else {
            "Hello!".to_string()
        };

        let html_content = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Reset Your Password</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .container {{ border: 1px solid #e0e0e0; border-radius: 5px; padding: 20px; }}
                    .header {{ text-align: center; margin-bottom: 20px; }}
                    .logo {{ font-size: 24px; font-weight: bold; color: #4a6cf7; }}
                    .button {{ display: inline-block; background-color: #4a6cf7; color: white; text-decoration: none; padding: 12px 24px; border-radius: 4px; font-weight: bold; margin: 20px 0; }}
                    .footer {{ margin-top: 30px; font-size: 12px; color: #888; text-align: center; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">AxeBase</div>
                    </div>
                    <p>{}</p>
                    <p>We received a request to reset your password. Click the button below to create a new password:</p>
                    <p style="text-align: center;">
                        <a href="{}" class="button">Reset Password</a>
                    </p>
                    <p>Or copy and paste the following link into your browser:</p>
                    <p>{}</p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request a password reset, you can safely ignore this email.</p>
                    <div class="footer">
                        <p>&copy; {} AxeBase. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            "#,
            greeting,
            reset_url,
            reset_url,
            chrono::Utc::now().year()
        );

        let text_content = format!(
            r#"
            {}

            We received a request to reset your password. Please use the following link to create a new password:

            {}

            This link will expire in 1 hour.

            If you didn't request a password reset, you can safely ignore this email.

            © {} AxeBase. All rights reserved.
            "#,
            greeting,
            reset_url,
            chrono::Utc::now().year()
        );

        let email = Email {
            to: to_email.to_string(),
            subject: "Reset Your Password".to_string(),
            html_content,
            text_content,
        };

        self.send_email(email).await
    }
}

/// Mock email service for testing and development
pub struct MockEmailService {
    pub sent_emails: std::sync::Mutex<Vec<Email>>,
}

impl Clone for MockEmailService {
    fn clone(&self) -> Self {
        Self {
            sent_emails: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl MockEmailService {
    pub fn new() -> Self {
        Self {
            sent_emails: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl EmailService for MockEmailService {
    async fn send_email(&self, email: Email) -> EmailResult<()> {
        // In a real test environment, you might want to log this
        println!("Mock email sent to: {}", email.to);
        println!("Subject: {}", email.subject);

        // Store the email for verification in tests
        let mut emails = self.sent_emails.lock().unwrap();
        emails.push(email);

        Ok(())
    }

    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_url: &str,
        user_name: Option<&str>,
    ) -> EmailResult<()> {
        let greeting = if let Some(name) = user_name {
            format!("Hello, {}!", name)
        } else {
            "Hello!".to_string()
        };

        let html_content = format!(
            "<p>{}</p><p>Please verify your email by clicking <a href='{}'>here</a>.</p>",
            greeting, verification_url
        );

        let text_content = format!(
            "{}\n\nPlease verify your email by visiting this link: {}",
            greeting, verification_url
        );

        let email = Email {
            to: to_email.to_string(),
            subject: "Verify Your Email Address".to_string(),
            html_content,
            text_content,
        };

        self.send_email(email).await
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_url: &str,
        user_name: Option<&str>,
    ) -> EmailResult<()> {
        let greeting = if let Some(name) = user_name {
            format!("Hello, {}!", name)
        } else {
            "Hello!".to_string()
        };

        let html_content = format!(
            "<p>{}</p><p>Reset your password by clicking <a href='{}'>here</a>.</p>",
            greeting, reset_url
        );

        let text_content = format!(
            "{}\n\nReset your password by visiting this link: {}",
            greeting, reset_url
        );

        let email = Email {
            to: to_email.to_string(),
            subject: "Reset Your Password".to_string(),
            html_content,
            text_content,
        };

        self.send_email(email).await
    }
}
