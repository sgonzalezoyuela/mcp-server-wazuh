use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::mcp::protocol::{error_codes, JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use crate::AppState;

// Structure to parse the parameters for a 'tools/call' request
#[derive(serde::Deserialize, Debug)]
struct ToolCallParams {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "arguments")]
    arguments: Option<Value>, // Input parameters for the specific tool
    #[serde(flatten)]
    _extra: std::collections::HashMap<String, Value>,
}

pub struct McpServerCore {
    app_state: Arc<AppState>,
}

impl McpServerCore {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    pub async fn process_request(&self, request: JsonRpcRequest) -> String {
        info!("Processing request: method={}", request.method);

        let response = match request.method.as_str() {
            "initialize" => self.handle_initialize(request).await,
            "shutdown" => self.handle_shutdown(request).await,
            "provideContext" => self.handle_provide_context(request).await,
            // Tool methods (prefix "tools/")
            "tools/list" => self.handle_list_tools(request).await,
            "tools/call" => self.handle_tool_call(request).await, // Use generic tool call handler
            // "tools/wazuhAlerts" => self.handle_wazuh_alerts_tool(request).await, 
            // Resource methods (prefix "resources/")
            "resources/list" => self.handle_get_resources(request).await,
            "resources/read" => self.handle_read_resource(request).await,
            // Prompt methods (prefix "prompts/")
            "prompts/list" => self.handle_list_prompts(request).await,
            _ => {
                error!("Method not found: {}", request.method);
                self.create_error_response(
                    error_codes::METHOD_NOT_FOUND,
                    format!("Method '{}' not found", request.method),
                    None,
                    request.id.clone(),
                )
            }
        };

        response
    }

    pub fn handle_parse_error(&self, error: serde_json::Error, raw_request: &str) -> String {
        error!("Failed to parse JSON-RPC request: {}", error);

        // Try to extract the ID from the raw request if possible
        let id = serde_json::from_str::<Value>(raw_request)
            .and_then(|v| {
                if let Some(id) = v.get("id") {
                    Ok(id.clone())
                } else {
                    // Use a different approach since custom is not available
                    Err(serde_json::Error::io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "No ID field found",
                    )))
                }
            })
            .unwrap_or(Value::Null);

        self.create_error_response(
            error_codes::PARSE_ERROR,
            format!("Parse error: {}", error),
            None,
            id,
        )
    }

    async fn handle_initialize(&self, request: JsonRpcRequest) -> String {
        debug!("Handling initialize request");


        // Define the wazuhAlertSummary tool - simpler with no output schema
        let wazuh_alert_summary_tool = crate::mcp::protocol::ToolDefinition {
            name: "wazuhAlertSummary".to_string(),
            description: Some("Returns a text summary of all Wazuh alerts.".to_string()),
            // Define a minimal valid input schema (empty object)
            input_schema: Some(json!({
                "type": "object",
                "properties": {}
            })),
            // No output schema needed as per requirements
            output_schema: None,
        };

        // Use the protocol structs for better type safety and structure
        let result = crate::mcp::protocol::InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: crate::mcp::protocol::Capabilities {
                tools: crate::mcp::protocol::ToolCapability {
                    supported: true,
                    definitions: vec![wazuh_alert_summary_tool], // Only include wazuhAlertSummary tool
                },
                resources: crate::mcp::protocol::SupportedFeature { supported: true },
                prompts: crate::mcp::protocol::SupportedFeature { supported: true },
            },
            server_info: crate::mcp::protocol::ServerInfo {
                name: "Wazuh MCP Server".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };

        self.create_success_response(result, request.id)
    }

    async fn handle_shutdown(&self, request: JsonRpcRequest) -> String {
        debug!("Handling shutdown request");
        self.create_success_response(Value::Null, request.id)
    }

    async fn handle_provide_context(&self, request: JsonRpcRequest) -> String {
        debug!("Handling provideContext request");

        // Lock the Wazuh client to make API calls
        let mut wazuh_client = self.app_state.wazuh_client.lock().await;

        // Get alerts from Wazuh
        match wazuh_client.get_alerts().await {
            Ok(alerts) => {
                let mcp_messages: Vec<Value> = alerts
                    .into_iter() 
                    .map(|alert| crate::mcp::transform::transform_to_mcp(alert, "alert".to_string()))
                    .collect();

                debug!("Transformed {} alerts into MCP messages for provideContext", mcp_messages.len());
                self.create_success_response(json!(mcp_messages), request.id)
            }
            Err(e) => {
                error!("Error getting alerts from Wazuh for provideContext: {}", e);
                self.create_error_response(
                    error_codes::INTERNAL_ERROR,
                    format!("Failed to get alerts from Wazuh: {}", e),
                    None,
                    request.id,
                )
            }
        }
    }

    async fn handle_get_resources(&self, request: JsonRpcRequest) -> String {
        debug!("Handling getResources request");
        // Return an empty list for now
        let resources_result = crate::mcp::protocol::ResourcesListResult {
            resources: vec![],
        };

        self.create_success_response(resources_result, request.id)
    }

    async fn handle_read_resource(&self, request: JsonRpcRequest) -> String {
        debug!("Handling readResource request: {:?}", request.params);

        #[derive(serde::Deserialize, Debug)]
        struct ReadResourceParams {
            uri: String,
            // We can add _meta here if needed later
            // _meta: Option<Value>,
        }

        let params: ReadResourceParams = match request.params {
            Some(params_value) => match serde_json::from_value(params_value) {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to parse params for resources/read: {}", e);
                    return self.create_error_response(
                        error_codes::INVALID_PARAMS,
                        format!("Invalid params for resources/read: {}", e),
                        None,
                        request.id,
                    );
                }
            },
            None => {
                error!("Missing params for resources/read");
                return self.create_error_response(
                    error_codes::INVALID_PARAMS,
                    "Missing params for resources/read, 'uri' is required".to_string(),
                    None,
                    request.id,
                );
            }
        };

        // Currently, no resources are supported for reading
        error!("Unsupported URI for resources/read: {}", params.uri);
        self.create_error_response(
            error_codes::INVALID_PARAMS, 
            format!("Unsupported or unknown resource URI: {}", params.uri),
            None,
            request.id,
        )
    }

    // Generic handler for executing tools via 'tools/call'
    async fn handle_tool_call(&self, request: JsonRpcRequest) -> String {
        debug!("Handling tools/call request: {:?}", request.params);


        let params: ToolCallParams = match request.clone().params {
            Some(params_value) => match serde_json::from_value(params_value) {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to parse params for tools/call: {}", e);
                    return self.create_error_response(
                        error_codes::INVALID_PARAMS,
                        format!("Invalid params for tools/call: {}", e),
                        None,
                        request.id,
                    );
                }
            },
            None => {
                error!("Missing params for tools/call");
                return self.create_error_response(
                    error_codes::INVALID_PARAMS,
                    "Missing params for tools/call, 'name' and 'arguments' are required".to_string(),
                    None,
                    request.id,
                );
            }
        };

        // Dispatch based on the tool name
        match params.name.as_str() {
            "wazuhAlertSummary" => {
                info!("Dispatching tools/call to wazuhAlertSummary handler");
                self.handle_wazuh_alert_summary_tool(request).await
            }
            // wazuhAlerts tool is disabled but we keep the handler code
            _ => {
                error!("Unsupported tool name requested via tools/call: {}", params.name);
                self.create_error_response(
                    error_codes::METHOD_NOT_FOUND, // Or a more specific tool error code if available
                    format!("Tool '{}' not found", params.name),
                    None,
                    request.id,
                )
            }
        }
    }


    // Handler for listing available tools
    async fn handle_list_tools(&self, request: JsonRpcRequest) -> String {
        debug!("Handling tools/list request");

        // Define the wazuhAlertSummary tool
        let wazuh_alert_summary_tool = crate::mcp::protocol::ToolDefinition {
            name: "wazuhAlertSummary".to_string(),
            description: Some("Returns a text summary of all Wazuh alerts.".to_string()),
            // Define a minimal valid input schema (empty object)
            input_schema: Some(json!({
                "type": "object",
                "properties": {}
            })),
            // No output schema needed as per requirements
            output_schema: None,
        };

        let tools_list = crate::mcp::protocol::ToolsListResult {
            tools: vec![wazuh_alert_summary_tool],
        };

        self.create_success_response(tools_list, request.id)
    }


    async fn handle_wazuh_alerts_tool(&self, request: JsonRpcRequest) -> String {
        debug!("Handling tools/wazuhAlerts request. Params: {:?}", request.params);

        let wazuh_client = self.app_state.wazuh_client.lock().await;

        match wazuh_client.get_alerts().await {
            Ok(raw_alerts) => {
                let simplified_alerts: Vec<Value> = raw_alerts
                    .into_iter()
                    .map(|alert| {
                        let source = alert.get("_source").unwrap_or(&alert);

                        // Extract ID: Try _source.id first, then _id
                        let id = source.get("id")
                            .and_then(|v| v.as_str())
                            .or_else(|| alert.get("_id").and_then(|v| v.as_str()))
                            .unwrap_or("") // Default to empty string if not found
                            .to_string();

                        // Extract Description: Look in _source.rule.description
                        let description = source.get("rule")
                            .and_then(|r| r.get("description"))
                            .and_then(|d| d.as_str())
                            .unwrap_or("") // Default to empty string if not found
                            .to_string();

                        json!({
                            "id": id,
                            "description": description,
                        })
                    })
                    .collect();

                debug!("Processed {} alerts into simplified format.", simplified_alerts.len());

                // Construct the final result with the "alerts" array
                let result = json!({ 
                    "alerts": simplified_alerts,
                    "text": "Hello World",
                });
                self.create_success_response(result, request.id)
            }
            Err(e) => {
                error!("Error getting alerts from Wazuh for tools/wazuhAlerts: {}", e);
                self.create_error_response(
                    error_codes::INTERNAL_ERROR,
                    format!("Failed to get alerts from Wazuh: {}", e),
                    None,
                    request.id,
                )
            }
        }
    }

    // Handler for the wazuhAlertSummary tool
    async fn handle_wazuh_alert_summary_tool(&self, request: JsonRpcRequest) -> String {
        debug!("Handling tools/wazuhAlertSummary request. Params: {:?}", request.params);

        let mut wazuh_client = self.app_state.wazuh_client.lock().await;


        match wazuh_client.get_alerts().await {
            Ok(raw_alerts) => {
                // Create a content item for each alert
                let content_items: Vec<Value> = if raw_alerts.is_empty() {
                    // If no alerts, return a single "no alerts" message
                    vec![json!({
                        "type": "text",
                        "text": "No Wazuh alerts found."
                    })]
                } else {
                    // Map each alert to a content item
                    raw_alerts
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
                            
                            // Format the alert as a text entry and create a content item
                            json!({
                                "type": "text",
                                "text": format!("Alert ID: {}\nTime: {}\nDescription: {}", id, timestamp, description)
                            })
                        })
                        .collect()
                };

                debug!("Processed {} alerts into individual content items.", content_items.len());

                // Construct the final result with the content array containing multiple text objects
                let result = json!({
                    "content": content_items
                });
                
                self.create_success_response(result, request.id)
            }
            Err(e) => {
                error!("Error getting alerts from Wazuh for tools/wazuhAlertSummary: {}", e);
                self.create_error_response(
                    error_codes::INTERNAL_ERROR,
                    format!("Failed to get alerts from Wazuh: {}", e),
                    None,
                    request.id,
                )
            }
        }
    }

    async fn handle_list_prompts(&self, request: JsonRpcRequest) -> String {
        debug!("Handling prompts/list request");

        // Define the single prompt according to the new structure
        let list_alerts_prompt = crate::mcp::protocol::PromptEntry {
            name: "list-wazuh-alerts".to_string(),
            description: Some("List the latest security alerts from Wazuh.".to_string()),
            arguments: vec![], // This prompt takes no arguments
        };

        let prompts = vec![list_alerts_prompt];

        let result = crate::mcp::protocol::PromptsListResult { prompts };

        self.create_success_response(result, request.id)
    }


    fn create_success_response<T: serde::Serialize>(&self, result: T, id: Value) -> String {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        };

        serde_json::to_string(&response).unwrap_or_else(|e| {
            error!("Failed to serialize JSON-RPC response: {}", e);
            format!(
                r#"{{"jsonrpc":"2.0","error":{{"code":-32603,"message":"Internal error: Failed to serialize response"}},"id":null}}"#
            )
        })
    }

    fn create_error_response(
        &self,
        code: i32,
        message: String,
        data: Option<Value>,
        id: Value,
    ) -> String {
        let response = JsonRpcResponse::<Value> {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data,
            }),
            id,
        };

        serde_json::to_string(&response).unwrap_or_else(|e| {
            error!("Failed to serialize JSON-RPC error response: {}", e);
            format!(
                r#"{{"jsonrpc":"2.0","error":{{"code":-32603,"message":"Internal error: Failed to serialize error response"}},"id":null}}"#
            )
        })
    }
}
