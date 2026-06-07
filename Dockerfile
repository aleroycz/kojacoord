# Multi-stage build for Kojacoord Proxy
FROM rust:1.75-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src
COPY cargo-kpl ./cargo-kpl

# Build in release mode
ENV SQLX_OFFLINE=true
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 kojacoord

# Create directories
RUN mkdir -p /app/data /app/plugins /app/logs \
    && chown -R kojacoord:kojacoord /app

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/kojacoord-proxy /app/kojacoord-proxy

# Copy plugin builder
COPY --from=builder /build/target/release/cargo-kpl /app/cargo-kpl

# Set permissions
RUN chmod +x /app/kojacoord-proxy /app/cargo-kpl \
    && chown kojacoord:kojacoord /app/kojacoord-proxy /app/cargo-kpl

# Switch to non-root user
USER kojacoord

# Expose default Minecraft proxy port and API ports
EXPOSE 25577 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/api/health || exit 1

# Run the proxy
CMD ["/app/kojacoord-proxy"]
