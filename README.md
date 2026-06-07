# Kojacoord Proxy

<div align="center">

[![Website](https://img.shields.io/badge/website-kojacraft.net-blue?style=for-the-badge)](https://www.kojacraft.net)
[![Discord](https://img.shields.io/badge/discord-join-purple?style=for-the-badge&logo=discord)](https://discord.gg/kojacraft)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Crates.io](https://img.shields.io/crates/v/kojacoord-proxy)](https://crates.io/crates/kojacoord-proxy)
[![Documentation](https://img.shields.io/badge/docs.rs-kojacoord--proxy-blue)](https://docs.rs/kojacoord-proxy)

</div>

A high-performance, modular Minecraft proxy server written in Rust, designed for multi-version protocol support, authentication management, and advanced network features. Built by [KojaCraft](https://www.kojacraft.net) to power our modded Minecraft network.

## Overview

Kojacoord Proxy sits between Minecraft clients and backend servers, providing protocol translation, authentication, anti-cheat mechanisms, and extensive configuration options. Built with Rust's async runtime (Tokio), it offers high concurrency and low latency for large-scale Minecraft networks.

## Features

- **Multi-Version Protocol Support**: Handles multiple Minecraft protocol versions with automatic negotiation and conversion
- **Authentication Pipeline**: Supports both online (Mojang) and offline authentication modes
- **Anti-Cheat Engine**: Built-in detection system for malicious client behavior
- **Protocol Conversion**: Seamless translation between different Minecraft versions
- **Forge Mod Support**: Comprehensive FML handshake handling for modded clients
- **Dashboard API**: RESTful API for remote management and monitoring
- **Server Management**: TCP-based server control interface
- **Database Integration**: MySQL support for persistent data storage
- **Connection Pooling**: Optimized backend connection management
- **Metrics Collection**: Real-time performance monitoring and logging

## Architecture

The project is organized as a Cargo workspace with the following crates:

- `kojacoord-protocol`: Protocol definitions, packet codecs, and version registries
- `kojacoord-netty`: Network layer with encryption and frame handling
- `kojacoord-auth`: Authentication pipeline and encryption utilities
- `kojacoord-proxy-core`: Core proxy logic and session management
- `kojacoord-anticheat`: Anti-cheat detection and violation tracking
- `kojacoord-config`: Configuration management and validation
- `kojacoord-api`: Public API for plugin development
- `kojacoord-dashboard-api`: Dashboard REST API endpoints
- `kojacoord-plugin-system`: Dynamic plugin loading system for custom functionality
- `kojacoord-cluster`: Cluster coordination for horizontal scaling
- `kojacoord-metrics`: Prometheus metrics export and analytics engine

## Building

### Prerequisites

- Rust 1.70 or later
- Cargo (included with Rust)
- MySQL (optional, for database features)

### Compilation

```bash
# Clone the repository
git clone https://github.com/aleroycz/kojacoord-proxy.git
cd kojacoord-proxy

# Build in release mode for optimal performance
cargo build --release

# The binary will be located at target/release/kojacoord-proxy
```

### Development Build

```bash
cargo build
cargo test
```

## Configuration

Create a `config.toml` file in the proxy's working directory. A sample configuration is provided below:

```toml
[proxy]
bind = "0.0.0.0:25577"
online_mode = true
compression_threshold = 256
session_timeout_secs = 30
prevent_proxy_connections = true

[[servers]]
name = "lobby"
address = "localhost:25565"
restricted = false
backend_type = "vanilla"

[database]
url = "mysql://user:password@localhost/kojacoord"
max_connections = 10

[anticheat]
enabled = true
strict_mode = false

[server_management]
enabled = true
bind = "127.0.0.1:8080"
auth_token = "your-secret-token"

[http_api]
enabled = true
bind = "127.0.0.1:8081"
auth_token = "your-api-token"
```

## Running

```bash
# Run the compiled binary
./target/release/kojacoord-proxy

# Or run directly with Cargo
cargo run --release
```

## Protocol Support

Currently supported Minecraft versions:

- 1.7.10 - 1.8 (Protocol 5-47)
- 1.12.2 (Protocol 340)
- 1.16.5 (Protocol 754)
- 1.21.x (Latest)

Protocol conversion is automatically performed when clients connect to backend servers running different versions.

## API Documentation

### HTTP API

The proxy exposes a RESTful API for management operations when `http_api.enabled` is set to `true`.

#### Authentication

All API requests require an `Authorization` header with the configured auth token:

```
Authorization: Bearer your-api-token
```

#### Endpoints

- `GET /api/players` - List online players
- `GET /api/players/{uuid}` - Get player details
- `POST /api/players/{uuid}/kick` - Kick a player
- `GET /api/servers` - List backend servers
- `GET /api/metrics` - Get performance metrics
- `GET /api/health` - Health check endpoint

### Server Management API

A TCP-based management interface is available on the configured `server_management.bind` address for advanced operations.

## Performance

- **Concurrent Connections**: Supports thousands of simultaneous connections
- **Low Latency**: Sub-millisecond proxy overhead
- **Memory Efficient**: Optimized buffer pooling and zero-copy where possible
- **Async I/O**: Non-blocking operations using Tokio

## Security

- RSA encryption for authentication handshakes
- Configurable proxy connection prevention
- Anti-cheat system with violation tracking
- Secure API authentication
- TLS support for database connections

## Contributing

We welcome contributions to Kojacoord Proxy. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow Rust standard formatting (`cargo fmt`)
- Use `cargo clippy` for linting
- Write unit tests for new functionality
- Document public APIs with rustdoc comments

## Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

## Bug Reporting

If you encounter a bug, please open an issue on GitHub with the following information:

- Proxy version
- Minecraft client version
- Backend server version
- Configuration (redacted sensitive information)
- Error logs
- Steps to reproduce

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Alex Guy Yann Le Roy

## Acknowledgments

- Built with [Tokio](https://tokio.rs/) for async runtime
- Protocol implementation inspired by existing Minecraft proxy projects
- Community feedback and contributions

## Citation

If you use Kojacoord Proxy in academic research or publications, please cite:

```
Kojacoord Proxy: A High-Performance Minecraft Proxy Server
Alex Guy Yann Le Roy
2026
```

## Contact

For questions, support, or discussions, please open an issue on GitHub or contact the maintainers.

## Roadmap

- [ ] Additional protocol version support
- [x] Enhanced anti-cheat heuristics
- [x] Plugin system for custom functionality
- [x] Web dashboard UI
- [x] Cluster support for horizontal scaling
- [x] Enhanced metrics and analytics
