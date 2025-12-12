//! Routes module
//! This module contains all API route handlers for the application

pub mod auth;

use axum::{Router, http, routing::get};
use tower_http::cors::CorsLayer;

use crate::AppState;

/// Configure all application routes
pub fn routes() -> Router<AppState> {
    // Configure CORS for development
    let cors = CorsLayer::new()
        .allow_origin(["http://localhost:5173".parse().unwrap()])
        .allow_methods([
            http::Method::GET,
            http::Method::POST,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::OPTIONS,
        ])
        .allow_headers([
            http::header::CONTENT_TYPE,
            http::header::AUTHORIZATION,
            http::header::ACCEPT,
        ])
        .allow_credentials(true);

    // Rate limit layer for authentication endpoints (more strict)
    // Commented out for now until needed
    // let rate_limit = ServiceBuilder::new()
    //     .layer(RateLimitLayer::new(20, Duration::from_secs(60))) // 20 requests per minute
    //     .into_inner();

    // Combine all routes
    Router::new()
        .merge(
            // Apply stricter rate limits to auth routes
            auth::router(),
        )
        .route("/health", get(|| async { "OK" }))
        .layer(cors)
}
