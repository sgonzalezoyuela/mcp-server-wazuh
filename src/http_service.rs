use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::logging_utils::{log_mcp_request, log_mcp_response};
use crate::AppState; // Added

pub fn create_http_router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/mcp", get(get_mcp_data))
        .route("/mcp", post(post_mcp_data))
        .with_state(app_state)
}

async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "wazuh-mcp-server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn get_mcp_data(
    State(app_state): State<Arc<AppState>>,
) -> Result<Json<Vec<Value>>, ApiError> {
    info!("Handling GET /mcp request");

    let wazuh_client = app_state.wazuh_client.lock().await;

    match wazuh_client.get_alerts().await {
        Ok(alerts) => {
            // Transform Wazuh alerts to MCP messages
            let mcp_messages = alerts
                .iter()
                .map(|alert| {
                    json!({
                        "protocol_version": "1.0",
                        "source": "Wazuh",
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "event_type": "alert",
                        "context": alert,
                        "metadata": {
                            "integration": "Wazuh-MCP"
                        }
                    })
                })
                .collect::<Vec<_>>();

            Ok(Json(mcp_messages))
        }
        Err(e) => {
            error!("Error getting alerts from Wazuh: {}", e);
            Err(ApiError::InternalServerError(format!(
                "Failed to get alerts from Wazuh: {}",
                e
            )))
        }
    }
}

async fn post_mcp_data(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<Value>,
) -> Result<Json<Vec<Value>>, ApiError> {
    info!("Handling POST /mcp request with payload");
    debug!("Payload: {:?}", payload);

    // Log the incoming payload
    let request_str = serde_json::to_string(&payload).unwrap_or_else(|e| {
        error!(
            "Failed to serialize POST request payload for logging: {}",
            e
        );
        format!(
            "{{\"error\":\"Failed to serialize request payload: {}\"}}",
            e
        )
    });
    log_mcp_request(&request_str);

    let result = get_mcp_data(State(app_state)).await;

    // Log the response
    let response_str = match &result {
        Ok(json_response) => serde_json::to_string(&json_response.0).unwrap_or_else(|e| {
            error!("Failed to serialize POST response for logging: {}", e);
            format!("{{\"error\":\"Failed to serialize response: {}\"}}", e)
        }),
        Err(api_error) => {
            let error_json_surrogate = json!({
                "error": format!("{:?}", api_error) // Or a more structured error
            });
            serde_json::to_string(&error_json_surrogate).unwrap_or_else(|e| {
                error!("Failed to serialize POST error response for logging: {}", e);
                format!(
                    "{{\"error\":\"Failed to serialize error response: {}\"}}",
                    e
                )
            })
        }
    };
    log_mcp_response(&response_str);

    result
}

// API Error handling
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    InternalServerError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}
