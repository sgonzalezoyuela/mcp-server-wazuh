use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::oneshot::Sender as OneshotSender;
use tracing::{debug, error, info};

use crate::logging_utils::{log_mcp_request, log_mcp_response};
use crate::mcp::mcp_server_core::McpServerCore;
use crate::mcp::protocol::JsonRpcRequest;
use crate::AppState;

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

                // Log the raw request using the utility
                log_mcp_request(request_str);

                // Process the request using the core module
                let response_json = match serde_json::from_str::<JsonRpcRequest>(request_str) {
                    Ok(rpc_request) => {
                        // Special handling for shutdown to exit the loop
                        let is_shutdown = rpc_request.method == "shutdown";
                        let response = mcp_core.process_request(rpc_request).await;

                        if is_shutdown {
                            // Log the response using the utility
                            log_mcp_response(&response);

                            // Send the response
                            if let Err(e) = stdout_writer
                                .write_all(format!("{}\n", response).as_bytes())
                                .await
                            {
                                error!("Error writing shutdown response to stdout: {}", e);
                            }
                            if let Err(e) = stdout_writer.flush().await {
                                error!("Error flushing stdout for shutdown: {}", e);
                            }

                            debug!("Signaling shutdown and exiting stdio_service due to 'shutdown' request.");
                            let _ = shutdown_tx.send(()); // Signal main to shutdown Axum
                            return; // Exit the loop and function
                        }

                        response
                    }
                    Err(e) => mcp_core.handle_parse_error(e, request_str),
                };

                // Log the raw response using the utility
                log_mcp_response(&response_json);

                info!("Sending to stdout (stdio_service): {}", response_json);
                // Prepare the response string with a newline
                let response_to_send = format!("{}\n", response_json);
                debug!(
                    "Attempting to write response to stdout. Length: {} bytes. Preview (up to 200 chars): '{}'",
                    response_to_send.len(),
                    response_to_send.chars().take(200).collect::<String>()
                );

                // Write the response and handle potential errors
                match stdout_writer.write_all(response_to_send.as_bytes()).await {
                    Ok(_) => {
                        debug!("Successfully wrote response bytes to stdout buffer.");
                        // Flush immediately after write
                        if let Err(e) = stdout_writer.flush().await {
                            error!("Error flushing stdout after successful write: {}", e);
                            debug!(
                                "Signaling shutdown and breaking loop due to stdout flush error."
                            );
                            let _ = shutdown_tx.send(());
                            break;
                        } else {
                            debug!("Successfully flushed stdout.");
                        }
                    }
                    Err(e) => {
                        error!("Error writing response to stdout: {}", e);
                        debug!("Signaling shutdown and breaking loop due to stdout write error.");
                        let _ = shutdown_tx.send(());
                        break;
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
