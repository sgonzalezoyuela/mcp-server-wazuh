use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::oneshot::Sender as OneshotSender;
use tracing::{debug, error, info};

use crate::logging_utils::{log_mcp_request, log_mcp_response};
use crate::mcp::mcp_server_core::McpServerCore;
use crate::mcp::protocol::{error_codes, JsonRpcRequest};
use crate::AppState;
use serde_json::Value;

pub async fn run_stdio_service(app_state: Arc<AppState>, shutdown_tx: OneshotSender<()>) {
    info!("Starting MCP server in stdio mode...");
    let mut stdin_reader = BufReader::new(tokio::io::stdin());
    let mut stdout_writer = tokio::io::stdout();
    let mcp_core = McpServerCore::new(app_state);

    let mut line_buffer = String::new();

    debug!("run_stdio_service: Initialized readers/writers. Entering main loop.");

    loop {
        debug!("stdio_service: Top of the loop. Clearing line buffer.");
        line_buffer.clear();
        debug!("stdio_service: About to read_line from stdin.");

        let read_result = stdin_reader.read_line(&mut line_buffer).await;
        debug!(?read_result, "stdio_service: read_line completed.");

        match read_result {
            Ok(0) => {
                debug!("stdio_service: read_line returned Ok(0) (EOF).");
                info!("Stdin closed (EOF), signaling shutdown and exiting stdio mode.");
                let _ = shutdown_tx.send(()); // Signal main to shutdown Axum
                debug!("stdio_service read 0 bytes, breaking loop.");
                break; // EOF
            }
            Ok(bytes_read) => {
                debug!(%bytes_read, "stdio_service: read_line returned Ok(bytes_read).");
                let request_str = line_buffer.trim();
                if request_str.is_empty() {
                    debug!("Received empty line from stdin, continuing.");
                    continue;
                }
                info!("Received from stdin (stdio_service): {}", request_str);
                log_mcp_request(request_str); // Log the raw incoming string

                let parsed_value: Value = match serde_json::from_str(request_str) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("JSON Parse Error: {}", e);
                        let response_json = mcp_core.handle_parse_error(e, request_str);
                        log_mcp_response(&response_json);
                        info!("Sending parse error response to stdout: {}", response_json);
                        let response_to_send = format!("{}\n", response_json);
                        if let Err(write_err) =
                            stdout_writer.write_all(response_to_send.as_bytes()).await
                        {
                            error!(
                                "Error writing parse error response to stdout: {}",
                                write_err
                            );
                            let _ = shutdown_tx.send(());
                            break;
                        }
                        if let Err(flush_err) = stdout_writer.flush().await {
                            error!("Error flushing stdout for parse error: {}", flush_err);
                            let _ = shutdown_tx.send(());
                            break;
                        }
                        continue;
                    }
                };

                if parsed_value.get("id").is_none()
                    || parsed_value.get("id").map_or(false, |id| id.is_null())
                {
                    // --- Handle Notification (No ID or ID is null) ---
                    let method = parsed_value
                        .get("method")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    info!("Received Notification: method='{}'", method);

                    match method {
                        "notifications/initialized" => {
                            debug!("Client 'initialized' notification received. No action taken, no response sent.");
                        }
                        "exit" => {
                            info!("'exit' notification received. Signaling shutdown immediately.");
                            let _ = shutdown_tx.send(());
                            return;
                        }
                        _ => {
                            debug!(
                                "Received unknown/unhandled notification method: '{}'. Ignoring.",
                                method
                            );
                        }
                    }
                    continue;
                } else {
                    let request_id = parsed_value.get("id").cloned().unwrap(); // We know ID exists and is not null here

                    match serde_json::from_value::<JsonRpcRequest>(parsed_value) {
                        Ok(rpc_request) => {
                            // --- Successfully parsed a Request ---
                            let is_shutdown = rpc_request.method == "shutdown";
                            let response_json = mcp_core.process_request(rpc_request).await;

                            // Log and send the response
                            log_mcp_response(&response_json);
                            info!("Sending response to stdout: {}", response_json);
                            let response_to_send = format!("{}\n", response_json);

                            if let Err(e) =
                                stdout_writer.write_all(response_to_send.as_bytes()).await
                            {
                                error!("Error writing response to stdout: {}", e);
                                let _ = shutdown_tx.send(());
                                break;
                            }
                            if let Err(e) = stdout_writer.flush().await {
                                error!("Error flushing stdout: {}", e);
                                let _ = shutdown_tx.send(());
                                break;
                            }

                            // Handle shutdown *after* sending the response
                            if is_shutdown {
                                debug!("'shutdown' request processed successfully. Signaling shutdown.");
                                let _ = shutdown_tx.send(()); // Signal main to shutdown Axum
                                return; // Exit the service loop
                            }
                        }
                        Err(e) => {
                            error!("Invalid JSON-RPC Request structure: {}", e);
                            // Use the ID we extracted earlier
                            let response_json = mcp_core.create_error_response(
                                error_codes::INVALID_REQUEST,
                                format!("Invalid Request structure: {}", e),
                                None,
                                request_id, // Use the ID from the original request
                            );

                            log_mcp_response(&response_json);
                            info!(
                                "Sending invalid request error response to stdout: {}",
                                response_json
                            );
                            let response_to_send = format!("{}\n", response_json);
                            if let Err(write_err) =
                                stdout_writer.write_all(response_to_send.as_bytes()).await
                            {
                                error!(
                                    "Error writing invalid request error response to stdout: {}",
                                    write_err
                                );
                                let _ = shutdown_tx.send(());
                                break;
                            }
                            if let Err(flush_err) = stdout_writer.flush().await {
                                error!(
                                    "Error flushing stdout for invalid request error: {}",
                                    flush_err
                                );
                                let _ = shutdown_tx.send(());
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!(error = %e, "stdio_service: read_line returned Err.");
                error!("Error reading from stdin for stdio_service: {}", e);
                debug!("Signaling shutdown and breaking loop due to stdin read error.");
                let _ = shutdown_tx.send(()); // Signal main to shutdown Axum
                break;
            }
        }
        debug!("stdio_service: Bottom of the loop, before next iteration.");
    }

    info!("run_stdio_service: Exited main loop. stdio_service task is finishing.");
}
