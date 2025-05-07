use anyhow::Result;
use chrono::{DateTime, Utc};
use httpmock::prelude::*;
use once_cell::sync::Lazy;
use serde_json::json;
use std::net::TcpListener;
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::sleep;

mod mcp_client;
use mcp_client::{McpClient, McpClientTrait, McpMessage};

static TEST_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn find_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to random port");
    let port = listener
        .local_addr()
        .expect("Failed to get local address")
        .port();
    drop(listener);
    port
}

struct MockWazuhServer {
    server: MockServer,
}

impl MockWazuhServer {
    fn new() -> Self {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(POST).path("/security/user/authenticate");

            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "jwt": "mock.jwt.token"
                }));
        });

        server.mock(|when, then| {
            when.method(GET).path("/wazuh-alerts-*_search");

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

    fn host(&self) -> String {
        let url = self.url();
        let parts: Vec<&str> = url.trim_start_matches("http://").split(':').collect();
        parts[0].to_string()
    }

    fn port(&self) -> u16 {
        let url = self.url();
        let parts: Vec<&str> = url.trim_start_matches("http://").split(':').collect();
        parts[1].parse().unwrap()
    }
}

fn setup_mock_wazuh_server() -> MockServer {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(POST).path("/security/user/authenticate");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "jwt": "mock.jwt.token" }));
    });

    server.mock(|when, then| {
        when.method(GET)
            .path_matches(Regex::new(r"/wazuh-alerts-.*_search").unwrap());
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "id": "12345",
                                "timestamp": "2024-01-01T10:00:00.000Z",
                                "rule": {
                                    "level": 9,
                                    "description": "Possible intrusion attempt detected",
                                    "groups": ["intrusion_detection", "pci_dss"]
                                },
                                "agent": { "id": "001", "name": "test-agent" },
                                "data": {
                                    "source_ip": "192.168.1.100",
                                    "destination_ip": "10.0.0.1",
                                    "port": 22
                                }
                            }
                        },
                        {
                            "_source": {
                                "id": "67890",
                                "timestamp": "2024-01-01T11:00:00.000Z",
                                "rule": {
                                    "level": 12,
                                    "description": "Malware detected on system",
                                    "groups": ["malware"]
                                },
                                "agent": { "id": "002", "name": "another-agent" },
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

    server
}

fn get_host_port(server: &MockServer) -> (String, u16) {
    let url = server.url("");
    let parts: Vec<&str> = url.trim_start_matches("http://").split(':').collect();
    let host = parts[0].to_string();
    let port = parts[1].parse().unwrap();
    (host, port)
}

fn start_mcp_server(wazuh_host: &str, wazuh_port: u16, mcp_port: u16) -> Child {
    Command::new("cargo")
        .args(["run", "--"])
        .env("WAZUH_HOST", wazuh_host)
        .env("WAZUH_PORT", wazuh_port.to_string())
        .env("WAZUH_USER", "admin")
        .env("WAZUH_PASS", "admin")
        .env("VERIFY_SSL", "false")
        .env("MCP_SERVER_PORT", mcp_port.to_string())
        .env("RUST_LOG", "info")
        .spawn()
        .expect("Failed to start MCP server")
}

#[tokio::test]

async fn test_mcp_server_with_mock_wazuh() -> Result<()> {
    let _guard = TEST_MUTEX.lock().unwrap();

    let mock_wazuh_server = setup_mock_wazuh_server();
    let (wazuh_host, wazuh_port) = get_host_port(&mock_wazuh_server);

    let mcp_port = find_available_port();

    let mut mcp_server = start_mcp_server(&wazuh_host, wazuh_port, mcp_port);

    sleep(Duration::from_secs(2)).await;

    let mcp_client = McpClient::new(format!("http://localhost:{}", mcp_port));

    let health_data = mcp_client.check_health().await?;
    assert_eq!(health_data["status"], "ok");
    assert_eq!(health_data["service"], "wazuh-mcp-server");

    let mcp_data = mcp_client.get_mcp_data().await?;

    assert_eq!(mcp_data.len(), 2);

    let first_message: &McpMessage = &mcp_data[0];
    assert_eq!(first_message.protocol_version, "1.0");
    assert_eq!(first_message.source, "Wazuh");
    assert_eq!(first_message.event_type, "alert");

    let context = &first_message.context;
    assert_eq!(context["id"], "12345");
    assert_eq!(context["category"], "intrusion_detection");
    assert_eq!(context["severity"], "high");
    assert_eq!(
        context["description"],
        "Possible intrusion attempt detected"
    );
    assert_eq!(context["agent"]["name"], "test-agent");

    let data = &context["data"];
    assert_eq!(data["source_ip"], "192.168.1.100");
    assert_eq!(data["destination_ip"], "10.0.0.1");
    assert_eq!(data["port"], 22);

    let second_message = &mcp_data[1];
    let context = &second_message.context;
    assert_eq!(context["id"], "67890");
    assert_eq!(context["category"], "malware");
    assert_eq!(context["severity"], "critical");
    assert_eq!(context["description"], "Malware detected on system");
    assert_eq!(context["agent"]["name"], "another-agent");

    let data = &context["data"];
    assert_eq!(data["file_path"], "/tmp/malicious.exe");
    assert_eq!(data["hash"], "abcdef123456");
    assert_eq!(data["signature"], "EICAR-Test-File");

    mcp_server.kill().expect("Failed to kill MCP server");

    Ok(())
}

#[tokio::test]
async fn test_mcp_server_wazuh_api_error() -> Result<()> {
    let _guard = TEST_MUTEX.lock().unwrap();

    let mock_wazuh_server = setup_mock_wazuh_server();
    let (wazuh_host, wazuh_port) = get_host_port(&mock_wazuh_server);

    mock_wazuh_server.mock(|when, then| {
        when.method(GET)
            .path_matches(Regex::new(r"/wazuh-alerts-.*_search").unwrap());
        then.status(500)
            .header("content-type", "application/json")
            .json_body(json!({"error": "Wazuh internal error"}));
    });

    let mcp_port = find_available_port();
    let mut mcp_server = start_mcp_server(&wazuh_host, wazuh_port, mcp_port);
    sleep(Duration::from_secs(2)).await;

    let mcp_client = McpClient::new(format!("http://localhost:{}", mcp_port));

    let result = mcp_client.get_mcp_data().await;
    assert!(result.is_err());
    let err_string = result.unwrap_err().to_string();
    assert!(
        err_string.contains("500")
            || err_string.contains("502")
            || err_string.contains("API request failed")
    );

    let health_result = mcp_client.check_health().await;
    assert!(health_result.is_ok());
    assert_eq!(health_result.unwrap()["status"], "ok");

    mcp_server.kill().expect("Failed to kill MCP server");
    Ok(())
}

#[tokio::test]
async fn test_mcp_client_error_handling() -> Result<()> {
    let _guard = TEST_MUTEX.lock().unwrap();

    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(GET).path("/mcp");
        then.status(500)
            .header("content-type", "application/json")
            .json_body(json!({
                "error": "Internal server error"
            }));
    });

    server.mock(|when, then| {
        when.method(GET).path("/health");
        then.status(503)
            .header("content-type", "application/json")
            .json_body(json!({
                "error": "Service unavailable"
            }));
    });

    let client = McpClient::new(server.url(""));

    let result = client.get_mcp_data().await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("500") || err.to_string().contains("MCP request failed"));

    let result = client.check_health().await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("503") || err.to_string().contains("Health check failed"));

    Ok(())
}

#[tokio::test]
async fn test_mcp_server_missing_alert_data() -> Result<()> {
    let _guard = TEST_MUTEX.lock().unwrap();

    let mock_wazuh_server = setup_mock_wazuh_server();
    let (wazuh_host, wazuh_port) = get_host_port(&mock_wazuh_server);

    mock_wazuh_server.mock(|when, then| {
        when.method(GET)
            .path_matches(Regex::new(r"/wazuh-alerts-.*_search").unwrap());
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "id": "missing_all",
                                "timestamp": "invalid-date-format"
                            }
                        },
                        {
                            "_source": {
                                "id": "missing_rule_fields",
                                "timestamp": "2024-05-05T11:00:00.000Z",
                                "rule": { },
                                "agent": { "id": "003", "name": "agent-minimal" },
                                "data": {}
                            }
                        },
                        {
                           "id": "no_source_nest",
                           "timestamp": "2024-05-05T12:00:00.000Z",
                           "rule": {
                               "level": 2,
                               "description": "Low severity event",
                               "groups": ["low_sev"]
                           },
                           "agent": { "id": "004" },
                           "data": { "info": "some data" }
                        }
                    ]
                }
            }));
    });

    let mcp_port = find_available_port();
    let mut mcp_server = start_mcp_server(&wazuh_host, wazuh_port, mcp_port);
    sleep(Duration::from_secs(2)).await;

    let mcp_client = McpClient::new(format!("http://localhost:{}", mcp_port));

    let mcp_data = mcp_client.get_mcp_data().await?;
    assert_eq!(mcp_data.len(), 3);

    let msg1 = &mcp_data[0];
    assert_eq!(msg1.context["id"], "missing_all");
    assert_eq!(msg1.context["category"], "unknown_category");
    assert_eq!(msg1.context["severity"], "unknown_severity");
    assert_eq!(msg1.context["description"], "");
    assert!(
        msg1.context["agent"].is_object() && msg1.context["agent"].as_object().unwrap().is_empty()
    );
    assert!(
        msg1.context["data"].is_object() && msg1.context["data"].as_object().unwrap().is_empty()
    );
    let ts1 = DateTime::parse_from_rfc3339(&msg1.timestamp)
        .unwrap()
        .with_timezone(&Utc);
    assert!((Utc::now() - ts1).num_seconds() < 5);

    let msg2 = &mcp_data[1];
    assert_eq!(msg2.context["id"], "missing_rule_fields");
    assert_eq!(msg2.context["category"], "unknown_category");
    assert_eq!(msg2.context["severity"], "unknown_severity");
    assert_eq!(msg2.context["description"], "");
    assert_eq!(msg2.context["agent"]["name"], "agent-minimal");
    assert!(
        msg2.context["data"].is_object() && msg2.context["data"].as_object().unwrap().is_empty()
    );
    assert_eq!(msg2.timestamp, "2024-05-05T11:00:00Z");

    let msg3 = &mcp_data[2];
    assert_eq!(msg3.context["id"], "no_source_nest");
    assert_eq!(msg3.context["category"], "low_sev");
    assert_eq!(msg3.context["severity"], "low");
    assert_eq!(msg3.context["description"], "Low severity event");
    assert_eq!(msg3.context["agent"]["id"], "004");
    assert!(msg3.context["agent"].get("name").is_none());
    assert_eq!(msg3.context["data"]["info"], "some data");
    assert_eq!(msg3.timestamp, "2024-05-05T12:00:00Z");

    mcp_server.kill().expect("Failed to kill MCP server");
    Ok(())
}
