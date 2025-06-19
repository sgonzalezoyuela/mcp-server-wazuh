FROM rust:1.86-slim as builder

WORKDIR /usr/src/app
COPY . .

RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev build-essential perl make && \
    cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/mcp-server-wazuh /app/mcp-server-wazuh
COPY .env.example /app/.env.example

RUN useradd -m wazuh
USER wazuh

EXPOSE 8000

CMD ["./mcp-server-wazuh"]
