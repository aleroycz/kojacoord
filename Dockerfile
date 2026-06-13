# Multi-stage build for Kojacoord Proxy
# NOTE: keep this Rust version at or above the highest MSRV among our
# transitive dependencies (e.g. time 0.3.47 needs 1.88, icu_provider
# needs 1.86). The release CI builds binaries with the latest stable
# toolchain, so the Docker builder must track it — pinning an old image
# here is what broke the multi-arch image build (rustc 1.85 < 1.88).
FROM rust:1.92-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    gcc \
    g++ \
    make \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src

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

# Switch to non-root user
USER kojacoord

# Expose default Minecraft proxy port and API ports
EXPOSE 25565 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/api/health || exit 1

# Run the proxy
CMD ["/app/kojacoord-proxy"]
