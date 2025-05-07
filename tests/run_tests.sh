#!/bin/bash

echo "Running all tests..."
cargo test

echo "Building MCP client CLI..."
cargo build --bin mcp_client_cli

if nc -z localhost 8000 2>/dev/null; then
    echo "Testing MCP client CLI against running server..."
    ./target/debug/mcp_client_cli health
    ./target/debug/mcp_client_cli get-data
else
    echo "MCP server is not running. Start it with 'cargo run' to test the CLI."
fi
