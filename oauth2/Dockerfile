# Multi-stage Dockerfile for StellaraeSecure oauth2

# --- Builder stage ---
FROM rust:1.86-bookworm AS builder

WORKDIR /build

# Copy crate manifest first for dependency caching.
COPY Cargo.toml ./

# Copy source and migration files required at compile time.
COPY src src/
COPY migrations migrations/

# Build release binary.
RUN cargo build --release

# --- Runtime stage ---
FROM debian:bookworm-slim

WORKDIR /app

# Copy binary from builder image.
COPY --from=builder /build/target/release/stellarae_oauth2 /app/stellarae_oauth2

# Create persistent data directory for SQLite.
RUN mkdir -p /app/data

# Expose oauth2 API port.
EXPOSE 4000

# Safe defaults for containerized deployment.
ENV OAUTH2_HOST=0.0.0.0
ENV OAUTH2_PORT=4000
ENV DATABASE_URL=sqlite:/app/data/oauth2.sqlite
ENV SERVICE_ID=oauth2-container
ENV ENVIRONMENT=production
ENV LOG_LEVEL=info

ENTRYPOINT ["/app/stellarae_oauth2"]
