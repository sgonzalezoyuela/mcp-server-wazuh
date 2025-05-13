use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize, Debug, Clone)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: Value,
}

#[derive(Serialize, Debug)]
pub struct JsonRpcResponse<T: Serialize> {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

#[derive(Serialize, Debug)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema", skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>, // Added inputSchema
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>, // Added outputSchema
}

#[derive(Serialize, Debug)]
pub struct ToolCapability {
    pub supported: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub definitions: Vec<ToolDefinition>, // List available tools
}

#[derive(Serialize, Debug)]
pub struct SupportedFeature {
    pub supported: bool,
}

#[derive(Serialize, Debug)]
pub struct Capabilities {
    pub tools: ToolCapability, // Use the new structure
    pub resources: SupportedFeature,
    pub prompts: SupportedFeature,
}

#[derive(Serialize, Debug)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Serialize, Debug)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: Capabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

#[derive(Serialize, Debug)]
pub struct ResourceEntry {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct ResourcesListResult {
    pub resources: Vec<ResourceEntry>,
}

#[derive(Serialize, Debug)]
pub struct ToolsListResult {
    pub tools: Vec<ToolDefinition>,
}

#[derive(Serialize, Debug, Clone)]
pub struct PromptArgument {
    pub name: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>, // Use Value for flexibility (string, bool, number)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>, // Optional description for the argument
}

#[derive(Serialize, Debug, Clone)]
pub struct PromptEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
}

#[derive(Serialize, Debug)]
pub struct PromptsListResult {
    pub prompts: Vec<PromptEntry>,
}

pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    pub const SERVER_ERROR_START: i32 = -32000;
    pub const SERVER_ERROR_END: i32 = -32099;
}
