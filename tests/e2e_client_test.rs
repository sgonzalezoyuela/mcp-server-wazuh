use anyhow::Result;
use httpmock::prelude::*;
use reqwest::Client;
use serde_json::{json, Value};
use std::process::{Child, Command};
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

struct MockWazuhServer {
    server: MockServer,
}

impl MockWazuhServer {
    fn new() -> Self {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(POST)
                .path("/security/user/authenticate")
                .header("Authorization", "Basic YWRtaW46YWRtaW4=");

            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "jwt": "mock.jwt.token"
                }));
        });

        server.mock(|when, then| {
            when.method(GET)
                .path("/wazuh-alerts-*_search")
                .header("Authorization", "Bearer mock.jwt.token");

            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "hits": {
                        "hits": [
                            {
                                "_source": {
                                    "id": "12345",
                                    "category": "intrusion_detection",
                                    "severity": "high",
                                    "description": "Possible intrusion attempt detected",
                                    "data": {
                                        "source_ip": "192.168.1.100",
                                        "destination_ip": "10.0.0.1",
                                        "port": 22
                                    },
                                    "notes": "Test alert"
                                }
                            },
                            {
                                "_source": {
                                    "id": "67890",
                                    "category": "malware",
                                    "severity": "critical",
                                    "description": "Malware detected on system",
                                    "data": {
                                        "file_path": "/tmp/malicious.exe",
                                        "hash": "abcdef123456",
                                        "signature": "EICAR-Test-File"
                                    }
                                }
                            }
                        ]
                    }
                }));
        });

        Self { server }
    }

    fn url(&self) -> String {
        self.server.url("")
    }
}

struct McpClient {
    client: Client,
    base_url: String,
}

impl McpClient {
    fn new(base_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, base_url }
    }

    async fn get_mcp_data(&self) -> Result<Vec<Value>> {
        let url = format!("{}/mcp", self.base_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("MCP request failed with status: {}", response.status());
        }

        let data = response.json::<Vec<Value>>().await?;
        Ok(data)
    }

    async fn check_health(&self) -> Result<Value> {
        let url = format!("{}/health", self.base_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("Health check failed with status: {}", response.status());
        }

        let data = response.json::<Value>().await?;
        Ok(data)
    }
}

fn start_mcp_server(wazuh_url: &str, port: u16) -> Child {
    let server_id = Uuid::new_v4().to_string();
    let wazuh_host_port: Vec<&str> = wazuh_url.trim_start_matches("http://").split(':').collect();
    let wazuh_host = wazuh_host_port[0];
    let wazuh_port = wazuh_host_port[1];

    Command::new("cargo")
        .args(["run", "--"])
        .env("WAZUH_HOST", wazuh_host)
        .env("WAZUH_PORT", wazuh_port)
        .env("WAZUH_USER", "admin")
        .env("WAZUH_PASS", "admin")
        .env("VERIFY_SSL", "false")
        .env("MCP_SERVER_PORT", port.to_string())
        .env("RUST_LOG", "info")
        .env("SERVER_ID", server_id)
        .spawn()
        .expect("Failed to start MCP server")
}

#[tokio::test]
async fn test_mcp_client_integration() -> Result<()> {
    let mock_wazuh = MockWazuhServer::new();
    let wazuh_url = mock_wazuh.url();

    let mcp_port = 8765;
    let mut mcp_server = start_mcp_server(&wazuh_url, mcp_port);

    sleep(Duration::from_secs(2)).await;

    let mcp_client = McpClient::new(format!("http://localhost:{}", mcp_port));

    let health_data = mcp_client.check_health().await?;
    assert_eq!(health_data["status"], "ok");
    assert_eq!(health_data["service"], "wazuh-mcp-server");

    let mcp_data = mcp_client.get_mcp_data().await?;

    assert_eq!(mcp_data.len(), 2);

    let first_message = &mcp_data[0];
    assert_eq!(first_message["protocol_version"], "1.0");
    assert_eq!(first_message["source"], "Wazuh");
    assert_eq!(first_message["event_type"], "alert");

    let context = &first_message["context"];
    assert_eq!(context["id"], "12345");
    assert_eq!(context["category"], "intrusion_detection");
    assert_eq!(context["severity"], "high");
    assert_eq!(
        context["description"],
        "Possible intrusion attempt detected"
    );

    let data = &context["data"];
    assert_eq!(data["source_ip"], "192.168.1.100");
    assert_eq!(data["destination_ip"], "10.0.0.1");
    assert_eq!(data["port"], 22);

    let second_message = &mcp_data[1];
    let context = &second_message["context"];
    assert_eq!(context["id"], "67890");
    assert_eq!(context["category"], "malware");
    assert_eq!(context["severity"], "critical");
    assert_eq!(context["description"], "Malware detected on system");

    let data = &context["data"];
    assert_eq!(data["file_path"], "/tmp/malicious.exe");
    assert_eq!(data["hash"], "abcdef123456");
    assert_eq!(data["signature"], "EICAR-Test-File");

    mcp_server.kill().expect("Failed to kill MCP server");

    Ok(())
}
