use anyhow::Result;
use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMessage {
    pub protocol_version: String,
    pub source: String,
    pub timestamp: String,
    pub event_type: String,
    pub context: Value,
    pub metadata: Value,
}

#[async_trait]
pub trait McpClientTrait {
    async fn get_mcp_data(&self) -> Result<Vec<McpMessage>>;

    async fn check_health(&self) -> Result<Value>;

    async fn query_mcp_data(&self, filters: Value) -> Result<Vec<McpMessage>>;
}

pub struct McpClient {
    client: Client,
    base_url: String,
}

impl McpClient {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, base_url }
    }
}

#[async_trait]
impl McpClientTrait for McpClient {
    async fn get_mcp_data(&self) -> Result<Vec<McpMessage>> {
        let url = format!("{}/mcp", self.base_url);
        let response = self.client.get(&url).send().await?;

        match response.status() {
            StatusCode::OK => {
                let data = response.json::<Vec<McpMessage>>().await?;
                Ok(data)
            }
            status => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                anyhow::bail!("MCP request failed with status {}: {}", status, error_text)
            }
        }
    }

    async fn check_health(&self) -> Result<Value> {
        let url = format!("{}/health", self.base_url);
        let response = self.client.get(&url).send().await?;

        match response.status() {
            StatusCode::OK => {
                let data = response.json::<Value>().await?;
                Ok(data)
            }
            status => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                anyhow::bail!("Health check failed with status {}: {}", status, error_text)
            }
        }
    }

    async fn query_mcp_data(&self, filters: Value) -> Result<Vec<McpMessage>> {
        let url = format!("{}/mcp", self.base_url);
        let response = self.client.post(&url).json(&filters).send().await?;

        match response.status() {
            StatusCode::OK => {
                let data = response.json::<Vec<McpMessage>>().await?;
                Ok(data)
            }
            status => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                anyhow::bail!("MCP query failed with status {}: {}", status, error_text)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use serde_json::json;
    use tokio;

    #[tokio::test]
    async fn test_mcp_client_get_data() {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(GET).path("/mcp");

            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!([
                    {
                        "protocol_version": "1.0",
                        "source": "Wazuh",
                        "timestamp": "2023-05-01T12:00:00Z",
                        "event_type": "alert",
                        "context": {
                            "id": "12345",
                            "category": "intrusion_detection",
                            "severity": "high",
                            "description": "Test alert",
                            "data": {
                                "source_ip": "192.168.1.100"
                            }
                        },
                        "metadata": {
                            "integration": "Wazuh-MCP",
                            "notes": "Test note"
                        }
                    }
                ]));
        });

        let client = McpClient::new(server.url(""));

        let result = client.get_mcp_data().await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].protocol_version, "1.0");
        assert_eq!(result[0].source, "Wazuh");
        assert_eq!(result[0].event_type, "alert");

        let context = &result[0].context;
        assert_eq!(context["id"], "12345");
        assert_eq!(context["category"], "intrusion_detection");
        assert_eq!(context["severity"], "high");
    }

    #[tokio::test]
    async fn test_mcp_client_health_check() {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(GET).path("/health");

            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "status": "ok",
                    "service": "wazuh-mcp-server",
                    "timestamp": "2023-05-01T12:00:00Z"
                }));
        });

        let client = McpClient::new(server.url(""));

        let result = client.check_health().await.unwrap();

        assert_eq!(result["status"], "ok");
        assert_eq!(result["service"], "wazuh-mcp-server");
    }
}
