//
// Purpose:
//
// This Rust application implements an MCP (Model Context Protocol) server that acts as a
// bridge to a Wazuh instance. It exposes various Wazuh functionalities as tools that can
// be invoked by MCP clients (e.g., AI models, automation scripts).
//
// Structure:
// - `main()`: Entry point of the application. Initializes logging (tracing),
//   sets up the `WazuhToolsServer`, and starts the MCP server using either stdio or HTTP-SSE transport.
//
// - `WazuhToolsServer`: The core struct that implements the `rmcp::ServerHandler` trait
//   and the `#[tool(tool_box)]` attribute.
//   - It holds the configuration for connecting to the Wazuh Indexer API.
//   - Its methods, decorated with `#[tool(...)]`, define the actual tools available
//     to MCP clients (e.g., `get_wazuh_alert_summary`).
//
// - Tool Parameter Structs (e.g., `GetAlertSummaryParams`):
//   - These structs define the expected input parameters for each tool.
//   - They use `serde::Deserialize` for parsing input and `schemars::JsonSchema`
//     for generating a schema that MCP clients can use to understand how to call the tools.
//
// - `wazuh` module:
//   - `WazuhIndexerClient`: Handles communication with the Wazuh Indexer API.
//   - Provides methods to fetch alerts and other security data from Wazuh.
//
// Workflow:
// 1. Server starts and listens for MCP requests on stdio or HTTP-SSE.
// 2. MCP client sends a `call_tool` request.
// 3. `WazuhToolsServer` dispatches to the appropriate tool method based on the tool name.
// 4. The tool method parses parameters, interacts with the Wazuh client to fetch data.
// 5. The result (success with data or error) is packaged into a `CallToolResult`
//    and sent back to the MCP client.
//
// Configuration:
// The server requires `WAZUH_HOST`, `WAZUH_PORT`, `WAZUH_USER`, `WAZUH_PASS`, and `VERIFY_SSL`
// environment variables to connect to the Wazuh instance. Logging is controlled by `RUST_LOG`.

use rmcp::{
    Error as McpError, ServerHandler, ServiceExt,
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    schemars, tool,
    transport::stdio,
};
use serde_json::json;
use std::sync::Arc;
use std::env;
use clap::Parser;
use dotenv::dotenv;

mod wazuh {
    pub mod client;
    pub mod error;
}

use wazuh::client::WazuhIndexerClient;

#[derive(Parser, Debug)]
#[command(name = "mcp-server-wazuh")]
#[command(about = "Wazuh SIEM MCP Server")]
struct Args {
    // Currently only stdio transport is supported
    // Future versions may add HTTP-SSE transport
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetAlertSummaryParams {
    #[schemars(description = "Maximum number of alerts to retrieve (default: 100)")]
    limit: Option<u32>,
}

#[derive(Clone)]
struct WazuhToolsServer {
    wazuh_client: Arc<WazuhIndexerClient>,
}

#[tool(tool_box)]
impl WazuhToolsServer {
    fn new() -> Result<Self, anyhow::Error> {
        dotenv().ok();

        let wazuh_host = env::var("WAZUH_HOST").unwrap_or_else(|_| "localhost".to_string());
        let wazuh_port = env::var("WAZUH_PORT")
            .unwrap_or_else(|_| "9200".to_string())
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("Invalid WAZUH_PORT: {}", e))?;
        let wazuh_user = env::var("WAZUH_USER").unwrap_or_else(|_| "admin".to_string());
        let wazuh_pass = env::var("WAZUH_PASS").unwrap_or_else(|_| "admin".to_string());
        let verify_ssl = env::var("VERIFY_SSL")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";

        let wazuh_client = WazuhIndexerClient::new(
            wazuh_host,
            wazuh_port,
            wazuh_user,
            wazuh_pass,
            verify_ssl,
        );

        Ok(Self {
            wazuh_client: Arc::new(wazuh_client),
        })
    }

    #[tool(
        name = "get_wazuh_alert_summary",
        description = "Retrieves a summary of Wazuh security alerts. Returns formatted alert information including ID, timestamp, and description."
    )]
    async fn get_wazuh_alert_summary(
        &self,
        #[tool(aggr)] params: GetAlertSummaryParams,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(100);
        
        tracing::info!(limit = %limit, "Retrieving Wazuh alert summary");

        match self.wazuh_client.get_alerts().await {
            Ok(raw_alerts) => {
                let alerts_to_process: Vec<_> = raw_alerts.into_iter().take(limit as usize).collect();
                
                let content_items: Vec<serde_json::Value> = if alerts_to_process.is_empty() {
                    // If no alerts, return a single "no alerts" message
                    vec![json!({
                        "type": "text",
                        "text": "No Wazuh alerts found."
                    })]
                } else {
                    // Map each alert to a content item
                    alerts_to_process
                        .into_iter()
                        .map(|alert| {
                            let source = alert.get("_source").unwrap_or(&alert);
                            
                            // Extract alert ID
                            let id = source.get("id")
                                .and_then(|v| v.as_str())
                                .or_else(|| alert.get("_id").and_then(|v| v.as_str()))
                                .unwrap_or("Unknown ID");
                            
                            // Extract rule description
                            let description = source.get("rule")
                                .and_then(|r| r.get("description"))
                                .and_then(|d| d.as_str())
                                .unwrap_or("No description available");
                            
                            // Extract timestamp if available
                            let timestamp = source.get("timestamp")
                                .and_then(|t| t.as_str())
                                .unwrap_or("Unknown time");
                            
                            // Extract agent name if available
                            let agent_name = source.get("agent")
                                .and_then(|a| a.get("name"))
                                .and_then(|n| n.as_str())
                                .unwrap_or("Unknown agent");
                            
                            // Extract rule level if available
                            let rule_level = source.get("rule")
                                .and_then(|r| r.get("level"))
                                .and_then(|l| l.as_u64())
                                .unwrap_or(0);
                            
                            // Format the alert as a text entry and create a content item
                            json!({
                                "type": "text",
                                "text": format!(
                                    "Alert ID: {}\nTime: {}\nAgent: {}\nLevel: {}\nDescription: {}",
                                    id, timestamp, agent_name, rule_level, description
                                )
                            })
                        })
                        .collect()
                };

                tracing::info!("Successfully processed {} alerts into content items", content_items.len());

                // Construct the final result with the content array containing multiple text objects
                let result = json!({
                    "content": content_items
                });
                
                Ok(CallToolResult::success(vec![
                    Content::json(result)
                        .map_err(|e| McpError::internal_error(e.to_string(), None))?,
                ]))
            }
            Err(e) => {
                let err_msg = format!("Error retrieving alerts from Wazuh: {}", e);
                tracing::error!("{}", err_msg);
                Ok(CallToolResult::error(vec![Content::text(err_msg)]))
            }
        }
    }
}

#[tool(tool_box)]
impl ServerHandler for WazuhToolsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_prompts()
                .enable_resources()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "This server provides tools to interact with a Wazuh SIEM instance for security monitoring and analysis.\n\
                Available tools:\n\
                - 'get_wazuh_alert_summary': Retrieves a summary of Wazuh security alerts. \
                Optionally takes 'limit' parameter to control the number of alerts returned (defaults to 100)."
                    .to_string(),
            ),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::DEBUG.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting Wazuh MCP Server...");

    // Create an instance of our Wazuh tools server
    let server = WazuhToolsServer::new()
        .expect("Error initializing Wazuh tools server");

    tracing::info!("Using stdio transport");
    let service = server.serve(stdio()).await
        .inspect_err(|e| {
            tracing::error!("serving error: {:?}", e);
        })?;

    service.waiting().await?;
    Ok(())
}
