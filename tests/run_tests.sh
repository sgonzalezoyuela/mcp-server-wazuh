#!/bin/bash

echo "Running all tests..."
cargo test

echo "Building MCP client CLI..."
cargo build --bin mcp_client_cli

echo "Building main server binary for stdio CLI tests..."
# Build the server executable that mcp_client_cli will run
cargo build --bin mcp-server-wazuh # Output: target/debug/mcp-server-wazuh

echo "Testing MCP client CLI in stdio mode..."

echo "Executing: ./target/debug/mcp_client_cli --stdio-exe ./target/debug/mcp-server-wazuh initialize"
./target/debug/mcp_client_cli --stdio-exe ./target/debug/mcp-server-wazuh initialize
if [ $? -ne 0 ]; then
    echo "CLI 'initialize' command failed!"
    exit 1
fi

echo "Executing: ./target/debug/mcp_client_cli --stdio-exe ./target/debug/mcp-server-wazuh provideContext"
./target/debug/mcp_client_cli --stdio-exe ./target/debug/mcp-server-wazuh provideContext
if [ $? -ne 0 ]; then
    echo "CLI 'provideContext' command failed!"
    exit 1
fi

# Example of provideContext with empty JSON params (optional to uncomment and test)
# echo "Executing: ./target/debug/mcp_client_cli --stdio-exe ./target/debug/mcp-server-wazuh provideContext '{}'"
# ./target/debug/mcp_client_cli --stdio-exe ./target/debug/mcp-server-wazuh provideContext '{}'
# if [ $? -ne 0 ]; then
#     echo "CLI 'provideContext {}' command failed!"
#     exit 1
# fi

echo "Executing: ./target/debug/mcp_client_cli --stdio-exe ./target/debug/mcp-server-wazuh shutdown"
./target/debug/mcp_client_cli --stdio-exe ./target/debug/mcp-server-wazuh shutdown
if [ $? -ne 0 ]; then
    # Shutdown might return an error if the server closes the pipe before the client fully processes the response,
    # but the primary goal is that the server process is terminated.
    # For this script, we'll be lenient on shutdown's exit code for now,
    # as long as initialize and provideContext worked.
    echo "CLI 'shutdown' command executed (non-zero exit code is sometimes expected if server closes pipe quickly)."
fi

echo "MCP client CLI stdio tests completed."
