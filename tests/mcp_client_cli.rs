use anyhow::Result;
use serde_json::Value;
use std::env;
use std::process;

mod mcp_client;
use mcp_client::{McpClient, McpClientTrait};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <command> [options]", args[0]);
        eprintln!("Commands:");
        eprintln!("  get-data    - Get MCP data from the server");
        eprintln!("  health      - Check server health");
        eprintln!("  query       - Query MCP data with filters");
        process::exit(1);
    }

    let command = &args[1];
    let mcp_url =
        env::var("MCP_SERVER_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

    println!("Connecting to MCP server at: {}", mcp_url);
    let client = McpClient::new(mcp_url);

    match command.as_str() {
        "get-data" => {
            println!("Fetching MCP data...");
            let data = client.get_mcp_data().await?;

            println!("Received {} MCP messages:", data.len());
            for (i, message) in data.iter().enumerate() {
                println!("\nMessage {}:", i + 1);
                println!("  Source: {}", message.source);
                println!("  Event Type: {}", message.event_type);
                println!("  Timestamp: {}", message.timestamp);

                let context = &message.context;
                println!("  Context:");
                println!("    ID: {}", context["id"]);
                println!("    Category: {}", context["category"]);
                println!("    Severity: {}", context["severity"]);
                println!("    Description: {}", context["description"]);

                if let Some(data) = context.get("data").and_then(|d| d.as_object()) {
                    println!("    Data:");
                    for (key, value) in data {
                        println!("      {}: {}", key, value);
                    }
                }
            }
        }
        "health" => {
            println!("Checking server health...");
            let health = client.check_health().await?;

            println!("Health status: {}", health["status"]);
            println!("Service: {}", health["service"]);
            println!("Timestamp: {}", health["timestamp"]);
        }
        "query" => {
            if args.len() < 3 {
                eprintln!("Error: Missing query parameters");
                eprintln!("Usage: {} query <json_filter>", args[0]);
                process::exit(1);
            }

            let filter_str = &args[2];
            let filters: Value = serde_json::from_str(filter_str)?;

            println!("Querying MCP data with filters: {}", filters);
            let data = client.query_mcp_data(filters).await?;

            println!("Received {} MCP messages:", data.len());
            for (i, message) in data.iter().enumerate() {
                println!("\nMessage {}:", i + 1);
                println!("  Source: {}", message.source);
                println!("  Event Type: {}", message.event_type);

                let context = &message.context;
                println!("  Context:");
                println!("    ID: {}", context["id"]);
                println!("    Category: {}", context["category"]);
                println!("    Severity: {}", context["severity"]);
            }
        }
        _ => {
            eprintln!("Error: Unknown command '{}'", command);
            process::exit(1);
        }
    }

    Ok(())
}
