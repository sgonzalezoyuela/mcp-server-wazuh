# Wazuh MCP Server Tests

This directory contains tests for the Wazuh MCP Server using the rmcp framework, including unit tests, integration tests with mock Wazuh API, and end-to-end MCP protocol tests.

## Test Files

- `rmcp_integration_test.rs`: Integration tests for the rmcp-based MCP server using a mock Wazuh API.
- `mock_wazuh_server.rs`: Mock Wazuh API server implementation, used by the integration tests.
- `mcp_stdio_test.rs`: Tests for MCP protocol communication via stdio, focusing on initialization, compliance, concurrent requests, and error handling for invalid/unsupported messages.
- `run_tests.sh`: A shell script that automates running the various test suites.

## Testing Strategy

### 1. Mock Wazuh Server Tests
Tests the MCP server with a mock Wazuh API to verify:
- Tool registration and schema generation
- Alert retrieval and formatting
- Error handling for API failures
- Parameter validation

### 2. MCP Protocol Tests
Tests the MCP protocol implementation (primarily in `mcp_stdio_test.rs`):
- Initialize handshake.
- Tools listing (basic, without requiring a live Wazuh connection).
- Handling of invalid JSON-RPC requests and unsupported methods.
- Behavior with concurrent requests.
- JSON-RPC 2.0 compliance.
(Note: Full tool execution, like `tools/call`, is primarily tested in `rmcp_integration_test.rs` using the mock Wazuh server.)

### 3. Unit Tests
Tests individual components and modules, typically run via `cargo test --lib`. These may include:
- Wazuh client logic (e.g., authentication, request formation, response parsing).
- Alert data transformation and formatting.
- Internal error handling mechanisms and utility functions.

## Running the Tests

### Run All Tests
```bash
cargo test
```

### Run Specific Test Categories
```bash
# Integration tests with mock Wazuh
cargo test --test rmcp_integration_test

# MCP protocol tests
cargo test --test mcp_stdio_test

# Unit tests
cargo test --lib
```

### Run Tests with Logging
```bash
RUST_LOG=debug cargo test -- --nocapture
```

## Test Environment Variables

The tests support the following environment variables:

- `RUST_LOG`: Log level for tests (default: info)
- `TEST_WAZUH_HOST`: Real Wazuh host for integration tests (optional)
- `TEST_WAZUH_PORT`: Real Wazuh port for integration tests (optional)
- `TEST_WAZUH_USER`: Real Wazuh username for integration tests (optional)
- `TEST_WAZUH_PASS`: Real Wazuh password for integration tests (optional)

## Mock Wazuh API Server

The mock server simulates a real Wazuh Indexer API with:

### Authentication Endpoint
- `POST /security/user/authenticate`
- Returns mock JWT token

### Alerts Endpoint  
- `POST /wazuh-alerts-*/_search` (Note: The Wazuh API typically uses POST for search queries with a body)
- Returns configurable mock alert data
- Supports different scenarios (success, empty, error)

### Configurable Responses
The mock server can be configured to return:
- Successful responses with sample alerts
- Empty responses (no alerts)
- Error responses (500, 401, etc.)
- Malformed responses for error testing

## Testing Without Real Wazuh

All tests can run without a real Wazuh instance by using the mock server. This allows for:

- **CI/CD Integration**: Tests run in any environment
- **Deterministic Results**: Predictable test data
- **Error Scenario Testing**: Simulate various failure modes
- **Fast Execution**: No network dependencies

## Testing With a Real Wazuh Instance (Manual End-to-End)

The automated test suites (`cargo test`) use mock servers or no Wazuh connection. To perform end-to-end testing with a real Wazuh instance, you need to run the server application itself and interact with it manually or via a separate client.

1.  **Set up your Wazuh environment:** Ensure you have a running Wazuh instance (Indexer/API).
2.  **Configure Environment Variables:** Set the standard runtime environment variables for the server to connect to your Wazuh instance:
    ```bash
    export WAZUH_HOST="your-wazuh-indexer-host"  # e.g., localhost or an IP address
    export WAZUH_PORT="9200"                     # Or your Wazuh Indexer port
    export WAZUH_USER="your-wazuh-api-user"
    export WAZUH_PASS="your-wazuh-api-password"
    export VERIFY_SSL="false"                    # Set to "true" if your Wazuh API uses a valid CA-signed SSL certificate
    # export RUST_LOG="debug"                    # For more detailed server logs
    ```

## Manual Testing

### Using stdio directly
The server communicates over stdin/stdout. You can send commands by piping them to the process:
```bash
# Example: Send an initialize request
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | cargo run --bin mcp-server-wazuh
```

### Using the test script
```bash
# Run the provided test script
./tests/run_tests.sh
```

This script will:
1. Start the MCP server with mock Wazuh configuration
2. Send a series of MCP commands
3. Verify responses
4. Clean up processes
