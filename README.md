# Wazuh MCP Server

A Rust-based server designed to bridge the gap between a Wazuh Security Information and Event Management (SIEM) system and applications requiring contextual security data, specifically tailored for the Claude Desktop Integration using the Model Context Protocol (MCP).

## Overview

Modern AI assistants like Claude can benefit significantly from real-time context about the user's environment. For security operations, this means providing relevant security alerts and events. Wazuh is a popular open-source SIEM, but its API output isn't directly consumable by systems expecting MCP format.

This server acts as a middleware:
1.  It connects to the Wazuh API.
2.  Authenticates using credentials (fetching a JWT token).
3.  Periodically fetches security alerts from Wazuh.
4.  Transforms these alerts from Wazuh's native format into the standardized MCP JSON format.
5.  Exposes a simple HTTP endpoint (`/mcp`) where clients like Claude Desktop can poll for the latest transformed security context.

## Architecture

The server facilitates communication between Claude Desktop (or any MCP client) and the Wazuh API.

```ascii
+-----------------+        +--------------------+        +-----------------+
| Claude Desktop  |        | Wazuh MCP Server   |        | Wazuh           |
| (MCP Client)    |        | (This Application) |        | (SIEM)          |
+-----------------+        +--------------------+        +-----------------+
        |                          |                          |
        |  1. GET /mcp Request     |                          |
        |------------------------->|                          |
        |                          |  2. Check/Refresh JWT    |
        |                          |------------------------->| 3. Authenticate (if needed via API)
        |                          |                          |
        |                          |  4. JWT Response (if auth)|
        |                          |<-------------------------|
        |                          |                          |
        |                          |  5. GET /wazuh-alerts-*_search (with JWT)
        |                          |------------------------->| 6. Fetch Alerts (via API)
        |                          |                          |
        |                          |  7. Wazuh Alert Data     |
        |                          |<-------------------------|
        |                          |                          |
        |                          |  8. Transform Data to MCP|
        |                          |  (Internal Logic)        |
        |                          |                          |
        |  9. MCP JSON Response    |                          |
        |<-------------------------|                          |
        |                          |                          |

```

**Data Flow:**

1.  An MCP client (e.g., Claude Desktop) sends an HTTP GET request to the `/mcp` endpoint of this server.
2.  The server checks if it has a valid JWT for the Wazuh API.
3.  If the JWT is missing or expired, it authenticates with the Wazuh API using configured credentials (`WAZUH_USER`, `WAZUH_PASS`) via the `/security/user/authenticate` endpoint.
4.  The Wazuh API returns a JWT.
5.  The server uses the valid JWT to make a request to the Wazuh alerts search endpoint (e.g., `/wazuh-alerts-*_search`).
6.  The Wazuh API executes the search (currently fetches all recent alerts).
7.  The Wazuh API returns the alert data in its native JSON format.
8.  The server's transformation logic (`src/mcp/transform.rs`) processes each alert, mapping Wazuh fields (like `rule.level`, `rule.description`, `agent.name`, `data`, `timestamp`) to the corresponding MCP fields (`severity`, `description`, `agent`, `data`, `timestamp`). It also sets default values for missing fields.
9.  The server responds to the MCP client with a JSON array of transformed alerts in the MCP format.

## Features

-   **Wazuh API Integration:** Connects securely to the Wazuh API.
-   **JWT Authentication:** Handles authentication with Wazuh using username/password to obtain a JWT.
-   **Automatic Token Refresh:** Monitors JWT validity and automatically re-authenticates when the token expires or is close to expiring. Retries API calls once upon receiving a 401 Unauthorized response.
-   **Alert Retrieval:** Fetches alerts from the Wazuh API (currently configured to retrieve all recent alerts via a `match_all` query).
-   **MCP Transformation:** Converts Wazuh alert JSON objects into MCP v1.0 compliant JSON messages. This includes:
    -   Mapping Wazuh `rule.level` to MCP `severity` (e.g., 0-3 -> "low", 8-11 -> "high").
    -   Extracting `rule.description`, `id`, `timestamp`, `agent` details, and the `data` payload.
    -   Taking the first group from `rule.groups` as the MCP `category`.
    -   Handling potential differences in Wazuh response structure (e.g., presence or absence of `_source` nesting).
    -   Providing default values (e.g., "unknown_severity", "unknown_category", current time for invalid timestamps).
-   **HTTP Server:** Exposes endpoints using the Axum web framework.
    -   `/mcp`: Serves the transformed MCP messages.
    -   `/health`: Provides a simple health check.
-   **Configuration:** Easily configurable via environment variables or a `.env` file.
-   **Containerization:** Includes a `Dockerfile` and `docker-compose.yml` for easy deployment.
-   **Logging:** Uses the `tracing` library for request and application logging (configurable via `RUST_LOG`).

## Requirements

-   Rust (latest stable recommended, see `Cargo.toml` for specific dependencies)
-   A running Wazuh server (v4.x recommended) with the API enabled and accessible.
-   Network connectivity between this server and the Wazuh API.

## Configuration

Configuration is managed through environment variables. A `.env` file can be placed in the project root for local development.

| Variable          | Description                                       | Default     | Required |
| ----------------- | ------------------------------------------------- | ----------- | -------- |
| `WAZUH_HOST`      | Hostname or IP address of the Wazuh API server.   | `localhost` | Yes      |
| `WAZUH_PORT`      | Port number for the Wazuh API.                    | `55000`     | Yes      |
| `WAZUH_USER`      | Username for Wazuh API authentication.            | `admin`     | Yes      |
| `WAZUH_PASS`      | Password for Wazuh API authentication.            | `admin`     | Yes      |
| `VERIFY_SSL`      | Set to `true` to verify the Wazuh API's SSL cert. | `false`     | No       |
| `MCP_SERVER_PORT` | Port for this MCP server to listen on.            | `8000`      | No       |
| `RUST_LOG`        | Log level (e.g., `info`, `debug`, `trace`).       | `info`      | No       |

**Note on `VERIFY_SSL`:** For production environments, it is strongly recommended to set `VERIFY_SSL=true` and ensure proper certificate validation. Setting it to `false` disables certificate checks, which is insecure.

## Building and Running

### Prerequisites

-   Install Rust: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
-   Install Docker and Docker Compose (optional, for containerized deployment): [https://docs.docker.com/get-docker/](https://docs.docker.com/get-docker/)

### Local Development

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/mcp-server-wazuh.git # Replace with your repo URL
    cd mcp-server-wazuh
    ```
2.  **Configure:**
    -   Copy the example environment file: `cp .env.example .env`
    -   Edit the `.env` file with your specific Wazuh API details (`WAZUH_HOST`, `WAZUH_PORT`, `WAZUH_USER`, `WAZUH_PASS`).
3.  **Build:**
    ```bash
    cargo build
    ```
4.  **Run:**
    ```bash
    cargo run
    # Or use the run script:
    # ./run.sh
    ```
    The server will start listening on the port specified by `MCP_SERVER_PORT` (default 8000).

### Docker Deployment

1.  **Clone the repository** (if not already done).
2.  **Configure:** Ensure you have a `.env` file with your Wazuh credentials in the project root, or set the environment variables directly in the `docker-compose.yml` or your deployment environment.
3.  **Build and Run:**
    ```bash
    docker-compose up --build -d
    ```
    This will build the Docker image and start the container in detached mode.

## API Endpoints

### `GET /mcp`

Fetches the latest alerts from the configured Wazuh API, transforms them into MCP format, and returns them as a JSON array.

-   **Method:** `GET`
-   **Success Response:** `200 OK`
    -   **Body:** `application/json` - An array of MCP message objects.
    ```json
    [
      {
        "protocol_version": "1.0",
        "source": "Wazuh",
        "timestamp": "2023-10-27T10:30:00Z", 
        "event_type": "alert",
        "context": {
          "id": "wazuh_alert_id_1",
          "category": "gdpr", 
          "severity": "high", 
          "description": "High severity rule triggered",
          "agent": { 
            "id": "001",
            "name": "server-db"
          },
          "data": { 
            "srcip": "1.2.3.4",
            "dstport": "22"
          }
        },
        "metadata": {
          "integration": "Wazuh-MCP",
          "notes": "Data fetched via Wazuh API"
         
        }
      },
      
    ]
    ```
-   **Error Responses:**
    -   `401 Unauthorized`: If Wazuh authentication fails persistently.
    -   `500 Internal Server Error`: If there's an issue fetching/parsing data from Wazuh, or an internal server problem.
    -   `502 Bad Gateway`: If the server cannot connect to the Wazuh API or the API returns an unexpected error.

### `GET /health`

A simple health check endpoint.

-   **Method:** `GET`
-   **Success Response:** `200 OK`
    -   **Body:** `application/json`
    ```json
    {
      "status": "ok",
      "service": "wazuh-mcp-server",
      "timestamp": "2023-10-27T12:00:00Z" 
    }
    ```
-   **Error Responses:** None expected for this endpoint itself, but the server might be unreachable if down.

## Running the All-in-One Demo (Wazuh + MCP Server)

For a complete local demo environment that includes Wazuh (Indexer, Manager, Dashboard) and the Wazuh MCP Server pre-configured to connect to it, you can use the `docker-compose.all-in-one.yml` file.

This setup is ideal for testing the end-to-end flow from Wazuh alerts to MCP messages.

**1. Launch the Environment:**

Navigate to the project root directory in your terminal and run:

```bash
docker-compose -f docker-compose.all-in-one.yml up -d
```

This command will:
- Download the necessary Wazuh and OpenSearch images (if not already present).
- Start the Wazuh Indexer, Wazuh Manager, and Wazuh Dashboard services.
- Build and start the Wazuh MCP Server.
- All services are configured to communicate with each other on an internal Docker network.

**2. Accessing Services:**

*   **Wazuh Dashboard:**
    *   URL: `https://localhost:8443` (Note: Uses HTTPS with a self-signed certificate, so your browser will likely show a warning).
    *   Default Username: `admin`
    *   Default Password: `AdminPassword123!` (This is set by `WAZUH_INITIAL_PASSWORD` in the `wazuh-indexer` service).

*   **Wazuh MCP Server:**
    *   The MCP server will be running and accessible on port `8000` by default (or the port specified by `MCP_SERVER_PORT` if you've set it as an environment variable on your host machine before running docker-compose).
    *   Example MCP endpoint: `http://localhost:8000/mcp`
    *   Example Health endpoint: `http://localhost:8000/health`
    *   **Configuration:** The `mcp-server` service within `docker-compose.all-in-one.yml` is already configured with the necessary environment variables to connect to the `wazuh-manager` service:
        *   `WAZUH_HOST=wazuh-manager`
        *   `WAZUH_PORT=55000`
        *   `WAZUH_USER=wazuh_user_demo`
        *   `WAZUH_PASS=wazuh_password_demo`
        *   `VERIFY_SSL=false`
        You do not need to set these in a separate `.env` file when using this all-in-one compose file, as they are defined directly in the service's environment.

**3. Stopping the Environment:**

To stop all services, run:

```bash
docker-compose -f docker-compose.all-in-one.yml down
```

To stop and remove volumes (deleting Wazuh data):

```bash
docker-compose -f docker-compose.all-in-one.yml down -v
```

This approach simplifies setup by bundling all necessary components and their configurations.

## Claude Desktop Integration

To use this Wazuh MCP Server with Claude Desktop (or any other MCP-compatible client), you need to configure the client to poll the `/mcp` endpoint exposed by this server.

1.  **Ensure the Wazuh MCP Server is running** and accessible from the machine where Claude Desktop is operating. This might involve:
    *   Running the server locally (e.g., `cargo run` or via Docker, including the all-in-one setup described above).
    *   Deploying the server to a reachable host.
2.  **Identify the server's address and port.**
    *   If using the all-in-one demo: `http://localhost:8000/mcp` (or your `MCP_SERVER_PORT`).
    *   If running `mcp-server` standalone: `http://localhost:8000` by default, or `http://<your-server-ip-or-hostname>:<MCP_SERVER_PORT>` if deployed elsewhere. The `MCP_SERVER_PORT` is configurable via environment variables (defaults to `8000`).
3.  **Configure Claude Desktop:**
    *   In Claude Desktop's settings or configuration area for external context sources, add a new MCP endpoint.
    *   Set the URL to `http://<server_address>:<port>/mcp`. For example:
        *   If running the all-in-one demo or locally: `http://localhost:8000/mcp`
        *   If running on a remote server `192.168.1.100` on port `8080`: `http://192.168.1.100:8080/mcp`
4.  **Verify Firewall Rules:** Ensure that any firewalls between Claude Desktop and the Wazuh MCP Server allow traffic on the configured `MCP_SERVER_PORT`.

Once configured, Claude Desktop should start polling the `/mcp` endpoint periodically to fetch the latest Wazuh security alerts in MCP format.

## Development & Testing

-   **Code Style:** Uses standard Rust formatting (`cargo fmt`).
-   **Linting:** Uses Clippy (`cargo clippy`).
-   **Testing:** Contains unit tests for transformation logic and integration tests using a mock Wazuh API server (`httpmock`) and a test MCP client.
    ```bash
    # Run all tests
    cargo test

    # Run specific integration test
    cargo test --test integration_test

    # Run tests with detailed logging
    RUST_LOG=debug cargo test
    ```
-   See `tests/README.md` for more details on running tests and using the test client CLI.

## License

This project is licensed under the [MIT License](LICENSE).
