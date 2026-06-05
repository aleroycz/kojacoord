# Kojacoord Proxy Usage Guide

This guide provides comprehensive instructions for deploying, configuring, and using Kojacoord Proxy in a Minecraft network environment.

## Table of Contents

1. [Installation](#installation)
2. [Initial Configuration](#initial-configuration)
3. [Basic Setup](#basic-setup)
4. [Advanced Configuration](#advanced-configuration)
5. [Protocol Conversion](#protocol-conversion)
6. [Authentication](#authentication)
7. [Anti-Cheat Configuration](#anti-cheat-configuration)
8. [API Usage](#api-usage)
9. [Monitoring and Metrics](#monitoring-and-metrics)
10. [Troubleshooting](#troubleshooting)

## Installation

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/kojacoord-proxy.git
cd kojacoord-proxy

# Build in release mode
cargo build --release

# The binary will be at target/release/kojacoord-proxy
```

### System Requirements

- **CPU**: 2+ cores recommended
- **RAM**: 512MB minimum, 2GB recommended for large networks
- **OS**: Linux, macOS, or Windows
- **Rust**: 1.70 or later (for building)
- **MySQL**: 5.7+ or 8.0+ (optional, for persistence)

## Initial Configuration

### Creating the Configuration File

Create a `config.toml` file in the same directory as the proxy binary:

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

[[servers]]
name = "survival"
address = "localhost:25566"
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
auth_token = "change-this-token"

[http_api]
enabled = true
bind = "127.0.0.1:8081"
auth_token = "change-this-api-token"
```

### Configuration Parameters

#### Proxy Settings

- **bind**: Address and port for the proxy to listen on (default: `0.0.0.0:25577`)
- **online_mode**: Enable Mojang authentication (default: `true`)
- **compression_threshold**: Packet size threshold for compression in bytes (default: `256`)
- **session_timeout_secs**: Session timeout in seconds (default: `30`)
- **prevent_proxy_connections**: Block connections through other proxies (default: `true`)

#### Server Configuration

Each backend server requires:
- **name**: Unique identifier for the server
- **address**: Backend server address (host:port)
- **restricted**: Whether the server requires special permissions (default: `false`)
- **backend_type**: Server type (`vanilla`, `paper`, `forge`, etc.)

#### Database Settings

- **url**: MySQL connection string
- **max_connections**: Maximum concurrent database connections (default: `10`)

## Basic Setup

### Single Server Setup

For a simple proxy setup with one backend server:

```toml
[proxy]
bind = "0.0.0.0:25577"
online_mode = true

[[servers]]
name = "main"
address = "localhost:25565"
restricted = false
backend_type = "vanilla"
```

### Multi-Server Network Setup

For a network with multiple servers:

```toml
[proxy]
bind = "0.0.0.0:25577"

[[servers]]
name = "lobby"
address = "lobby-server:25565"
restricted = false

[[servers]]
name = "survival"
address = "survival-server:25565"
restricted = false

[[servers]]
name = "creative"
address = "creative-server:25565"
restricted = false
```

Players connect to the proxy and are routed to the default server (first in the list).

## Advanced Configuration

### Restricted Servers

Configure servers that require specific permissions:

```toml
[[servers]]
name = "vip-server"
address = "vip-server:25565"
restricted = true
backend_type = "vanilla"
```

Players need the appropriate role to access restricted servers.

### Protocol Version Specific Settings

Configure different compression thresholds per protocol version:

```toml
[proxy]
compression_threshold = 256
```

The proxy automatically handles protocol-specific compression during conversion.

## Protocol Conversion

### Automatic Version Negotiation

The proxy automatically detects client protocol versions and negotiates with backend servers:

1. Client connects with their protocol version
2. Proxy identifies the version during handshake
3. Proxy connects to backend server with appropriate protocol
4. Packets are converted transparently between versions

### Supported Version Conversions

- **1.7.10 ↔ 1.8**: Basic packet translation
- **1.12.2 ↔ 1.16.5**: Slot data format conversion, JSON message handling
- **1.16.5 ↔ 1.21.x**: Attribute system updates, modern packet structures

### Conversion Limitations

Some features may not translate between distant versions:
- New block types (may appear as placeholders)
- New entity types (may not render correctly)
- Complex NBT data structures

## Authentication

### Online Mode (Mojang Authentication)

```toml
[proxy]
online_mode = true
```

Players must authenticate with Mojang servers. The proxy handles:
- Encryption handshake
- Session verification
- UUID resolution

### Offline Mode

```toml
[proxy]
online_mode = false
```

For development or private networks without Mojang authentication:
- Players use any username
- UUIDs are generated from usernames
- No encryption is performed

### Custom Authentication

For custom authentication systems, implement the `AuthPipeline` trait:

```rust
use kojacoord_auth::{AuthPipeline, AuthResult};

pub struct CustomAuth;

impl AuthPipeline for CustomAuth {
    async fn authenticate(&self, username: &str) -> AuthResult {
        // Custom authentication logic
        AuthResult::Success(uuid, profile)
    }
}
```

## Anti-Cheat Configuration

### Basic Configuration

```toml
[anticheat]
enabled = true
strict_mode = false
```

### Anti-Cheat Features

- **Packet Validation**: Checks for malformed packets
- **Movement Analysis**: Detects impossible movement patterns
- **Combat Analysis**: Identifies abnormal combat behavior
- **Mod Detection**: Identifies unauthorized client modifications

### Violation Handling

Configure automatic actions for violations:

```toml
[anticheat]
enabled = true
strict_mode = false
kick_threshold = 10
ban_threshold = 50
```

## API Usage

### HTTP API

Enable the HTTP API in configuration:

```toml
[http_api]
enabled = true
bind = "127.0.0.1:8081"
auth_token = "your-secure-token"
```

### Authentication

All API requests require the auth token:

```bash
curl -H "Authorization: Bearer your-secure-token" http://localhost:8081/api/players
```

### Endpoints

#### List Online Players

```bash
GET /api/players
```

Response:
```json
{
  "players": [
    {
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "username": "player1",
      "server": "lobby",
      "protocol_version": 763
    }
  ]
}
```

#### Get Player Details

```bash
GET /api/players/{uuid}
```

#### Kick Player

```bash
POST /api/players/{uuid}/kick
Content-Type: application/json

{
  "reason": "Kicked by administrator"
}
```

#### List Servers

```bash
GET /api/servers
```

Response:
```json
{
  "servers": [
    {
      "name": "lobby",
      "address": "localhost:25565",
      "player_count": 5,
      "online": true
    }
  ]
}
```

#### Get Metrics

```bash
GET /api/metrics
```

Response:
```json
{
  "total_connections": 1000,
  "active_connections": 50,
  "packets_relayed": 50000,
  "bytes_transferred": 10485760,
  "failed_connections": 5
}
```

#### Health Check

```bash
GET /api/health
```

Response:
```json
{
  "status": "healthy",
  "uptime_seconds": 3600
}
```

### Server Management API

The TCP-based management interface provides advanced operations:

```toml
[server_management]
enabled = true
bind = "127.0.0.1:8080"
auth_token = "your-management-token"
```

Connect via Telnet or Netcat:
```bash
telnet localhost 8080
```

Commands:
- `STATUS` - Get proxy status
- `PLAYERS` - List online players
- `SERVERS` - List backend servers
- `KICK <uuid> [reason]` - Kick a player
- `SHUTDOWN` - Gracefully shutdown the proxy

## Monitoring and Metrics

### Log Output

The proxy uses structured logging with tracing:

```bash
# Run with RUST_LOG environment variable
RUST_LOG=info ./kojacoord-proxy

# For debug output
RUST_LOG=debug ./kojacoord-proxy
```

### Metrics Collection

Metrics are automatically collected and logged every 30 seconds:

```
Metrics snapshot total=1000 active=50 packets=50000 bytes=10485760 failed=5
```

### Integration with Monitoring Systems

Export metrics to external systems by implementing a custom metrics collector:

```rust
use kojacoord_proxy_core::ProxyMetrics;

async fn export_metrics(metrics: &ProxyMetrics) {
    let snapshot = metrics.snapshot();
    // Send to Prometheus, InfluxDB, etc.
}
```

## Troubleshooting

### Connection Issues

**Problem**: Players cannot connect

**Solutions**:
1. Check firewall settings for the proxy port
2. Verify `bind` address in configuration
3. Check backend server connectivity
4. Review logs for error messages

### Authentication Failures

**Problem**: Players fail to authenticate

**Solutions**:
1. Verify `online_mode` setting matches your setup
2. Check internet connectivity for Mojang API access
3. Review authentication logs
4. Ensure session servers are accessible

### Performance Issues

**Problem**: High latency or lag

**Solutions**:
1. Increase `compression_threshold` to reduce CPU usage
2. Check system resources (CPU, RAM, network)
3. Review metrics for connection counts
4. Consider database connection pooling optimization

### Protocol Conversion Errors

**Problem**: Players get disconnected during version conversion

**Solutions**:
1. Verify both client and server versions are supported
2. Check logs for specific conversion errors
3. Ensure backend server is running the expected version
4. Review protocol compatibility matrix

### Database Connection Issues

**Problem**: Proxy cannot connect to MySQL

**Solutions**:
1. Verify database URL in configuration
2. Check MySQL server is running
3. Ensure database user has correct permissions
4. Review firewall rules for database port (3306)

## Best Practices

1. **Security**: Use strong, unique auth tokens for API endpoints
2. **Monitoring**: Regularly review metrics and logs
3. **Backups**: Backup configuration files and database regularly
4. **Testing**: Test configuration changes in a staging environment
5. **Updates**: Keep the proxy updated for security patches
6. **Resource Allocation**: Monitor system resources and scale as needed

## Additional Resources

- [README.md](../README.md) - Main project documentation
- [LICENSE](../LICENSE) - MIT License information
- [GitHub Issues](https://github.com/aleroycz/kojacoord-proxy/issues) - Bug reports and feature requests

## Support

For additional support:
- Open an issue on GitHub
- Check existing documentation
- Review configuration examples
- Consult the community forum
