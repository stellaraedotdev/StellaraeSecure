# Multi-stage Dockerfile for StellaraeSecure staffdb

# --- Builder stage ---
FROM rust:1.86 as builder

WORKDIR /build

# Copy Cargo manifest
COPY Cargo.toml ./

# Copy source code
COPY src src/

# Build release binary
RUN cargo build --release

# --- Runtime stage ---
FROM debian:bookworm-slim

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/staffdb /app/staffdb

# Create directory for SQLite database
RUN mkdir -p /app/data

# Expose port
EXPOSE 3000

# Set environment defaults for containerized deployment
ENV STAFFDB_HOST=0.0.0.0
ENV STAFFDB_PORT=3000
ENV DATABASE_URL=sqlite:/app/data/staffdb.sqlite
ENV SERVICE_ID=staffdb-container
ENV ENVIRONMENT=production
ENV LOG_LEVEL=info

# Run the service
ENTRYPOINT ["/app/staffdb"]
