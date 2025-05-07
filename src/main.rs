
mod wazuh;
mod mcp;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    routing::get,
    Router,
    extract::State,
    response::Json,
    http::StatusCode,
};
use dotenv::dotenv;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracing::{info, error};

use wazuh::client::WazuhApiClient;
use mcp::transform::transform_to_mcp;

// Application state shared across handlers
struct AppState {
    wazuh_client: Mutex<WazuhApiClient>,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    
    tracing_subscriber::fmt::init();
    
    let wazuh_host = env::var("WAZUH_HOST").unwrap_or_else(|_| "localhost".to_string());
    let wazuh_port = env::var("WAZUH_PORT")
        .unwrap_or_else(|_| "55000".to_string())
        .parse::<u16>()
        .expect("WAZUH_PORT must be a valid port number");
    let wazuh_user = env::var("WAZUH_USER").unwrap_or_else(|_| "admin".to_string());
    let wazuh_pass = env::var("WAZUH_PASS").unwrap_or_else(|_| "admin".to_string());
    let verify_ssl = env::var("VERIFY_SSL")
        .unwrap_or_else(|_| "false".to_string())
        .to_lowercase() == "true";
    let mcp_server_port = env::var("MCP_SERVER_PORT")
        .unwrap_or_else(|_| "8000".to_string())
        .parse::<u16>()
        .expect("MCP_SERVER_PORT must be a valid port number");
    

    let wazuh_client = WazuhApiClient::new(
        wazuh_host.clone(),
        wazuh_port,
        wazuh_user.clone(),
        wazuh_pass.clone(),
        verify_ssl,
    );
    
    let app_state = Arc::new(AppState {
        wazuh_client: Mutex::new(wazuh_client),
    });
    
    let app = Router::new()
        .route("/mcp", get(mcp_endpoint))
        .route("/health", get(health_check))
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], mcp_server_port));
    info!("Attempting to bind server to {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!("Failed to bind to address {}: {}", addr, e);
        panic!("Failed to bind to address {}: {}", addr, e);
    });
    info!("Wazuh MCP Server listening on {}", addr);
 

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap_or_else(|e| {
            error!("Server error: {}", e);
            panic!("Server error: {}", e);
        });
}

/// MCP endpoint for Claude Desktop.
/// Retrieves the latest Wazuh alerts, converts them into MCP messages, and returns as JSON.
async fn mcp_endpoint(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Value>>, (StatusCode, Json<Value>)> {
    let alert_query = json!({
        "query": {
            "match_all": {}
        }
    });
    
    let mut wazuh_client = state.wazuh_client.lock().await;
    
    match wazuh_client.get_alerts(alert_query).await {
        Ok(alerts_data) => {
            let hits_array = alerts_data
                .get("hits")
                .and_then(|h| h.get("hits"))
                .and_then(|h| h.as_array())
                .cloned()
                .unwrap_or_else(Vec::new);
            
            let mcp_messages = hits_array
                .iter()
                .filter_map(|hit| {
                    hit.get("_source").map(|source| {
                        transform_to_mcp(source.clone(), "alert".to_string())
                    })
                })
                .collect::<Vec<_>>();
            
            Ok(Json(mcp_messages))
        }
        Err(e) => {
            error!("Error in /mcp endpoint: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            ))
        }
    }
}

/// Health check endpoint.
/// Returns a simple JSON response to indicate the server is running.
async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "wazuh-mcp-server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
