use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use dotenv::dotenv;
use std::backtrace::Backtrace;
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, error, info, Level};
use tracing_subscriber::EnvFilter;

// Use components from the library crate
use mcp_server_wazuh::http_service::create_http_router;
use mcp_server_wazuh::stdio_service::run_stdio_service;
use mcp_server_wazuh::wazuh::client::WazuhIndexerClient;
use mcp_server_wazuh::AppState;

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Set a custom panic hook to ensure panics are logged
    std::panic::set_hook(Box::new(|panic_info| {
        // Using eprintln directly as tracing might not be available or working during a panic
        eprintln!(
            "\n================================================================================\n"
        );
        eprintln!("PANIC OCCURRED IN MCP SERVER");
        eprintln!(
            "\n--------------------------------------------------------------------------------\n"
        );
        eprintln!("Panic Info: {:#?}", panic_info);
        eprintln!(
            "\n--------------------------------------------------------------------------------\n"
        );
        // Capture and print the backtrace
        // Requires RUST_BACKTRACE=1 (or full) to be set in the environment
        let backtrace = Backtrace::capture();
        eprintln!("Backtrace:\n{:?}", backtrace);
        eprintln!(
            "\n================================================================================\n"
        );

        // If tracing is still operational, try to log with it too.
        // This might not always work if the panic is deep within tracing or stdio.
        error!(panic_info = %panic_info, backtrace = ?backtrace, "Global panic hook caught a panic");
    }));
    debug!("Custom panic hook set.");

    // Configure tracing to output to stderr
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env().add_directive(Level::DEBUG.into()))
        .init();

    info!("Starting Wazuh MCP Server");

    debug!("Loading environment variables...");
    let wazuh_host = env::var("WAZUH_HOST").unwrap_or_else(|_| "localhost".to_string());
    let wazuh_port = env::var("WAZUH_PORT")
        .unwrap_or_else(|_| "9200".to_string())
        .parse::<u16>()
        .expect("WAZUH_PORT must be a valid port number");
    let wazuh_user = env::var("WAZUH_USER").unwrap_or_else(|_| "admin".to_string());
    let wazuh_pass = env::var("WAZUH_PASS").unwrap_or_else(|_| "admin".to_string());
    let verify_ssl = env::var("VERIFY_SSL")
        .unwrap_or_else(|_| "false".to_string())
        .to_lowercase()
        == "true";
    let mcp_server_port = env::var("MCP_SERVER_PORT")
        .unwrap_or_else(|_| "8000".to_string())
        .parse::<u16>()
        .expect("MCP_SERVER_PORT must be a valid port number");

    debug!(
        wazuh_host,
        wazuh_port,
        wazuh_user,
        // wazuh_pass is sensitive, avoid logging
        verify_ssl,
        mcp_server_port,
        "Environment variables loaded."
    );

    info!("Initializing Wazuh API client...");
    let wazuh_client = WazuhIndexerClient::new(
        wazuh_host.clone(),
        wazuh_port,
        wazuh_user.clone(),
        wazuh_pass.clone(),
        verify_ssl,
    );

    let app_state = Arc::new(AppState {
        wazuh_client: Mutex::new(wazuh_client),
    });
    debug!("AppState created.");

    // Set up HTTP routes using the new http_service module
    info!("Setting up HTTP routes...");
    let app = create_http_router(app_state.clone());
    debug!("HTTP routes configured.");

    let addr = SocketAddr::from(([0, 0, 0, 0], mcp_server_port));
    info!("Attempting to bind HTTP server to {}", addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            error!("Failed to bind to address {}: {}", addr, e);
            panic!("Failed to bind to address {}: {}", addr, e);
        });
    info!("Wazuh MCP Server listening on {}", addr);

    // Spawn the stdio transport handler using the new stdio_service
    info!("Spawning stdio service handler...");
    let app_state_for_stdio = app_state.clone();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let stdio_handle = tokio::spawn(async move {
        run_stdio_service(app_state_for_stdio, shutdown_tx).await;
        info!("run_stdio_service ASYNC TASK has completed its execution.");
    });

    // Configure Axum with graceful shutdown
    let axum_shutdown_signal = async {
        shutdown_rx
            .await
            .map_err(|e| error!("Shutdown signal sender dropped: {}", e))
            .ok(); // Wait for the signal, log if sender is dropped
        info!("Graceful shutdown signal received for Axum server. Axum will now attempt to shut down.");
    };

    info!("Starting Axum server with graceful shutdown.");
    let axum_task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(axum_shutdown_signal)
            .await
            .unwrap_or_else(|e| {
                error!("Axum Server run error: {}", e);
            });
        info!("Axum server task has completed and shut down.");
    });

    // Make handles mutable so select can take &mut
    let mut stdio_handle = stdio_handle;
    let mut axum_task = axum_task;

    // Wait for either the stdio service or Axum server to complete.
    tokio::select! {
        biased; // Prioritize checking stdio_handle first if both are ready

        stdio_res = &mut stdio_handle => {
            match stdio_res {
                Ok(_) => info!("Stdio service task completed. Axum's graceful shutdown should have been triggered if stdio initiated it."),
                Err(e) => error!("Stdio service task failed or panicked: {:?}", e),
            }
            // Stdio has finished. If it didn't send a shutdown signal (e.g. due to panic before sending),
            // Axum might still be running. The shutdown_tx being dropped will also trigger axum_shutdown_signal.
            info!("Waiting for Axum server to fully shut down after stdio completion...");
            match axum_task.await {
                Ok(_) => info!("Axum server task completed successfully after stdio completion."),
                Err(e) => error!("Axum server task failed or panicked after stdio completion: {:?}", e),
            }
        }


        axum_res = &mut axum_task => {
            match axum_res {
                Ok(_) => info!("Axum server task completed (possibly due to graceful shutdown or error)."),
                Err(e) => error!("Axum server task failed or panicked: {:?}", e),
            }
            // Axum has finished. The main function will now exit.
            // We should wait for stdio_handle to complete or be cancelled.
            info!("Axum finished. Waiting for stdio_handle to complete or be cancelled...");
            match stdio_handle.await {
                Ok(_) => info!("Stdio service task also completed after Axum finished."),
                Err(e) => {
                    if e.is_cancelled() {
                        info!("Stdio service task was cancelled after Axum finished (expected if main is exiting).");
                    } else {
                        error!("Stdio service task failed or panicked after Axum finished: {:?}", e);
                    }
                }
            }
        }
    }
    info!("Main function is exiting.");
}
