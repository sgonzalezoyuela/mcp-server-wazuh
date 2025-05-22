// This file is kept for compatibility with existing tests and binaries
// The main MCP server functionality has been moved to main.rs using the rmcp framework

pub mod wazuh;

// Re-export for backward compatibility
pub use wazuh::client::WazuhIndexerClient;
pub use wazuh::error::WazuhApiError;
