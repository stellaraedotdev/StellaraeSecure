# Multi-stage Dockerfile for StellaraeSecure staffdb

# --- Builder stage ---
FROM rust:1.70 as builder

WORKDIR /build

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src src/

# Build release binary
RUN cargo build --release

# --- Runtime stage ---
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies (minimal)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /build/target/release/staffdb /app/staffdb

# Create directory for SQLite database
RUN mkdir -p /app/data

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/healthz || exit 1

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
