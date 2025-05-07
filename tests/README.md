# Wazuh MCP Server Tests

This directory contains tests for the Wazuh MCP Server, including end-to-end tests that simulate a client interacting with the server.

## Test Files

- `e2e_client_test.rs`: End-to-end test for MCP client interacting with Wazuh MCP server
- `integration_test.rs`: Integration test for Wazuh MCP Server with a mock Wazuh API
- `mcp_client.rs`: Reusable MCP client implementation
- `mcp_client_cli.rs`: Command-line tool for interacting with the MCP server

## Running the Tests

To run all tests:

```bash
cargo test
```

To run a specific test:

```bash
cargo test --test e2e_client_test
cargo test --test integration_test
```

## Using the MCP Client CLI

The MCP Client CLI can be used to interact with the MCP server for testing purposes:

```bash
# Build the CLI
cargo build --bin mcp_client_cli

# Run the CLI
MCP_SERVER_URL=http://localhost:8000 ./target/debug/mcp_client_cli get-data
MCP_SERVER_URL=http://localhost:8000 ./target/debug/mcp_client_cli health
MCP_SERVER_URL=http://localhost:8000 ./target/debug/mcp_client_cli query '{"severity": "high"}'
```

## Test Environment Variables

The tests use the following environment variables:

- `MCP_SERVER_URL`: URL of the MCP server (default: http://localhost:8000)
- `WAZUH_HOST`: Hostname of the Wazuh API server
- `WAZUH_PORT`: Port of the Wazuh API server
- `WAZUH_USER`: Username for Wazuh API authentication
- `WAZUH_PASS`: Password for Wazuh API authentication
- `VERIFY_SSL`: Whether to verify SSL certificates (default: false)
- `RUST_LOG`: Log level for the tests (default: info)

## Mock Wazuh API Server

The tests use a mock Wazuh API server to simulate the Wazuh API. The mock server provides:

- Authentication endpoint: `/security/user/authenticate`
- Alerts endpoint: `/wazuh-alerts-*_search`

The mock server returns predefined responses for these endpoints, allowing the tests to run without a real Wazuh API server.
