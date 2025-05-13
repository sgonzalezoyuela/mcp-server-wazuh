use anyhow::{anyhow, Result};
use clap::Parser;
use serde_json::Value;
use std::io::{self, Write}; // For stdout().flush() and stdin().read_line()

use mcp_server_wazuh::mcp::client::{McpClient, McpClientTrait};
use serde::Deserialize; // For ParsedRequest

#[derive(Parser, Debug)]
#[clap(
    name = "mcp-client-cli",
    version = "0.1.0",
    about = "Interactive CLI for MCP server. Enter JSON-RPC requests, or 'health'/'quit'."
)]
struct CliArgs {
    #[clap(long, help = "Path to the MCP server executable for stdio mode.")]
    stdio_exe: Option<String>,

    #[clap(
        long,
        env = "MCP_SERVER_URL",
        default_value = "http://localhost:8000",
        help = "URL of the MCP server for HTTP mode."
    )]
    http_url: String,
}

// For parsing raw JSON request strings
#[derive(Deserialize, Debug)]
struct ParsedRequest {
    // jsonrpc: String, // Not strictly needed for sending
    method: String,
    params: Option<Value>,
    id: Value, // ID can be string or number
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli_args = CliArgs::parse();
    let mut client: McpClient;
    let is_stdio_mode = cli_args.stdio_exe.is_some();

    if let Some(ref exe_path) = cli_args.stdio_exe {
        println!("Using stdio mode with executable: {}", exe_path);
        client = McpClient::new_stdio(exe_path, None).await?;
        println!("Sending 'initialize' request to stdio server...");
        match client.initialize().await {
            Ok(init_result) => {
                println!("Initialization successful:");
                println!("  Protocol Version: {}", init_result.protocol_version);
                println!("  Server Name: {}", init_result.server_info.name);
                println!("  Server Version: {}", init_result.server_info.version);
            }
            Err(e) => {
                eprintln!("Stdio Initialization failed: {}. You may need to send a raw 'initialize' JSON-RPC request or check server logs.", e);
                // Allow continuing, user might want to send raw init or other commands.
            }
        }
    } else {
        println!("Using HTTP mode with URL: {}", cli_args.http_url);
        client = McpClient::new_http(cli_args.http_url.clone());
        // No automatic initialize for HTTP mode as per McpClientTrait.
        // `initialize` is typically a stdio-specific concept in MCP.
    }

    println!("\nInteractive MCP Client. Enter a JSON-RPC request, 'health' (HTTP only), or 'quit'.");
    println!("Press CTRL-D for EOF to exit.");

    let mut input_buffer = String::new();
    loop {
        input_buffer.clear();
        print!("mcp> ");
        io::stdout().flush().map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;

        match io::stdin().read_line(&mut input_buffer) {
            Ok(0) => { // EOF (Ctrl-D)
                println!("\nEOF detected. Exiting.");
                break;
            }
            Ok(_) => {
                let line = input_buffer.trim();
                if line.is_empty() {
                    continue;
                }

                if line.eq_ignore_ascii_case("quit") {
                    println!("Exiting.");
                    break;
                }

                if line.eq_ignore_ascii_case("health") {
                    if is_stdio_mode {
                        println!("'health' command is intended for HTTP mode. For stdio, you would need to send a specific JSON-RPC request if the server supports a health method via stdio.");
                    } else {
                        println!("Checking server health (HTTP GET to /health)...");
                        let health_url = format!("{}/health", cli_args.http_url); // Use the parsed http_url
                        match reqwest::get(&health_url).await {
                            Ok(response) => {
                                let status = response.status();
                                let response_text = response.text().await.unwrap_or_else(|_| "Failed to read response body".to_string());
                                if status.is_success() {
                                    match serde_json::from_str::<Value>(&response_text) {
                                        Ok(json_val) => println!("Health response ({}):\n{}", status, serde_json::to_string_pretty(&json_val).unwrap_or_else(|_| response_text.clone())),
                                        Err(_) => println!("Health response ({}):\n{}", status, response_text),
                                    }
                                } else {
                                    eprintln!("Health check failed with status: {}", status);
                                    eprintln!("Response: {}", response_text);
                                }
                            }
                            Err(e) => eprintln!("Health check request failed: {}", e),
                        }
                    }
                    continue;
                }

                // Assume it's a JSON-RPC request
                println!("Attempting to send as JSON-RPC: {}", line);
                match serde_json::from_str::<ParsedRequest>(line) {
                    Ok(parsed_req) => {
                        match client
                            .send_json_rpc_request(
                                &parsed_req.method,
                                parsed_req.params.clone(),
                                parsed_req.id.clone(),
                            )
                            .await
                        {
                            Ok(response_value) => {
                                println!(
                                    "Server Response: {}",
                                    serde_json::to_string_pretty(&response_value).unwrap_or_else(
                                        |e_pretty| format!("Failed to pretty-print response ({}): {:?}", e_pretty, response_value)
                                    )
                                );
                            }
                            Err(e) => {
                                eprintln!("Error processing JSON-RPC request '{}': {}", line, e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to parse input as a JSON-RPC request: {}. Input: '{}'", e, line);
                        eprintln!("Please enter a valid JSON-RPC request string, 'health', or 'quit'.");
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading input: {}. Exiting.", e);
                break;
            }
        }
    }

    if is_stdio_mode {
        println!("Sending 'shutdown' request to stdio server...");
        match client.shutdown().await {
            Ok(_) => println!("Shutdown command acknowledged by server."),
            Err(e) => eprintln!("Error during shutdown: {}. Server might have already exited or closed the connection.", e),
        }
    }

    Ok(())
}
