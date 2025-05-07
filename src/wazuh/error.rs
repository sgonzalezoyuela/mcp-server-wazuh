use thiserror::Error;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum WazuhApiError {
    #[error("Failed to create HTTP client: {0}")]
    HttpClientCreationError(reqwest::Error),

    #[error("HTTP request error: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("JWT token not found in Wazuh API response")]
    JwtNotFound,

    #[error("Wazuh API Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("Failed to decode JWT: {0}")]
    JwtDecodingError(#[from] jsonwebtoken::errors::Error),

    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Wazuh API error: {0}")]
    ApiError(String),

    #[error("Alert with ID '{0}' not found")]
    AlertNotFound(String),
}

impl IntoResponse for WazuhApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            WazuhApiError::HttpClientCreationError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal server error: {}", e),
            ),
            WazuhApiError::RequestError(e) => {
                if e.is_connect() || e.is_timeout() {
                    (
                        StatusCode::BAD_GATEWAY,
                        format!("Could not connect to Wazuh API: {}", e),
                    )
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Wazuh API request error: {}", e),
                    )
                }
            }
            WazuhApiError::JwtNotFound => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve JWT token from Wazuh API response".to_string(),
            ),
            WazuhApiError::AuthenticationError(msg) => (
                StatusCode::UNAUTHORIZED,
                format!("Wazuh API authentication failed: {}", msg),
            ),
            WazuhApiError::JwtDecodingError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to decode JWT token: {}", e),
            ),
            WazuhApiError::JsonError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse Wazuh API response: {}", e),
            ),
            WazuhApiError::ApiError(msg) => {
                (StatusCode::BAD_GATEWAY, format!("Wazuh API error: {}", msg))
            }
            WazuhApiError::AlertNotFound(id) => (
                StatusCode::NOT_FOUND,
                format!("Alert with ID '{}' not found", id),
            ),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
