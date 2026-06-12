# Kojacoord Proxy

<div align="center">

[![Website](https://img.shields.io/badge/website-kojacraft.net-blue?style=for-the-badge)](https://www.kojacraft.net)
[![Discord](https://img.shields.io/badge/discord-join-purple?style=for-the-badge&logo=discord)](https://discord.gg/Xp6wFH3nM6)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Crates.io](https://img.shields.io/crates/v/kojacoord-proxy)](https://crates.io/crates/kojacoord-proxy)
[![Documentation](https://img.shields.io/badge/docs.rs-kojacoord--proxy-blue)](https://docs.rs/kojacoord-proxy)

</div>

Hey there! Kojacoord Proxy is a high-performance Minecraft proxy server we built in Rust. It handles multi-version protocol support, authentication, and all sorts of advanced networking stuff. We created it at [KojaCraft](https://www.kojacraft.net) to power our modded Minecraft network, and we're excited to share it with you.

## What is this?

Think of Kojacoord Proxy as the middleman between Minecraft clients and your backend servers. It handles protocol translation, authentication, and gives you tons of configuration options. Since it's built with Rust's async runtime (Tokio), it can handle tons of connections with minimal lag—perfect for large servers.

## What can it do?

- **Multi-Version Support**: Handles Minecraft 1.6.x through 1.21.x with automatic protocol conversion—no more version mismatches
- **Authentication**: Works with both online (Mojang) and offline mode, plus profile property signature verification to keep things secure
- **Player Forwarding**: Supports Velocity (HMAC-signed), BungeeCord (legacy), and no forwarding modes—whatever your backend needs
- **Plugin System**: Load custom plugins via `.kpl` packages or WASM modules, with hot-reload support so you don't have to restart
- **Modloader Detection**: Automatically detects Forge and other modded clients
- **Limbo System**: Hold players in a waiting state while transferring between servers—no more random kicks
- **PROXY Protocol**: Optional PROXY protocol support for getting real client IPs behind load balancers
- **Database**: SQLite by default, with MySQL support for persistent data
- **Telemetry**: Anonymous, opt-in usage metrics to help us understand adoption (you can turn this off)
- **Rate Limiting**: Built-in rate limiting for plugin channel messages to prevent spam

## How it's organized

The project is split into several crates (Rust's word for packages):

- `kojacoord-protocol`: Protocol definitions, packet codecs, and version registries
- `kojacoord-netty`: Network layer with encryption and frame handling
- `kojacoord-auth`: Authentication pipeline and encryption utilities
- `kojacoord-proxy-core`: Core proxy logic and session management
- `kojacoord-config`: Configuration management and validation
- `kojacoord-api`: Public API for plugin development
- `kojacoord-plugin-system`: Dynamic plugin loading with WASM runtime support
- `kojacoord-cluster`: Cluster coordination for horizontal scaling
- `kojacoord-metrics`: Analytics and telemetry collection

## Key features

- **Region Selector**: Routes players to the closest server based on their IP region (US-East, EU-West, Asia) to reduce latency. Uses a simple IPv4 heuristic with smart fallback ordering—picks the least-loaded server in the preferred region, then tries other regions if needed
- **Routing**: Flexible rule-based player routing—match by username patterns (case-insensitive glob with `*` wildcards) or IP ranges (IPv4/IPv6 CIDR). Rules are evaluated in order, first match wins. Falls back to default server, then any online server
- **Encryption**: Pluggable cipher registry for inter-node communication (cluster gossip, control-plane payloads)—separate from Minecraft login encryption. Supports AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, and experimental post-quantum KEM. You can even register custom algorithms at runtime
- **Limbo**: Holds players in a synthetic world when backends are unavailable instead of kicking them. Synthesizes JoinGame, position, abilities, and keepalive packets per version. Polls every 3 seconds for a backend to come back online. Uses a distinct world name to avoid chunk cache collisions when transferring back to real servers

## Building it

### What you need

- Rust 1.75 or later
- Cargo (comes with Rust)
- MySQL (optional, only if you want database features)

### Compiling

```bash
# Clone the repo
git clone https://github.com/aleroycz/kojacoord.git
cd kojacoord-proxy-experimentals

# Build in release mode for best performance
cargo build --release

# The binary will be at target/release/kojacoord-proxy
```

### For development

```bash
cargo build
cargo test
```

## Setting it up

Create a `config.toml` file in the proxy's working directory. Here's a sample to get you started:

```toml
[proxy]
bind = "0.0.0.0:25565"
online_mode = true
compression_threshold = 256
max_players = 1000
prevent_proxy_connections = false
session_timeout_secs = 5

[listeners]
motd = "KojacoordNetwork"
tab_list = "GLOBAL_PING"

[forwarding]
mode = "none"  # Options: none, velocity, bungeecord
velocity_secret = ""

[telemetry]
enabled = true
endpoint = "https://metric.kojacoord.net"
interval_secs = 1800

[database]
url = ""  # Empty for SQLite, or mysql://user:pass@host/kojacoord
max_connections = 10

[[servers]]
name = "lobby"
address = "127.0.0.1:25566"
restricted = false
display_name = "Lobby"
motd = "The KojaCraft hub — pick a game to play!"
game_type = "lobby"

[[servers]]
name = "survival"
address = "127.0.0.1:25567"
backend_type = "spigot"
display_name = "Survival"
motd = "Hardcore survival with custom mechanics"
game_type = "survival"
modpack = "kojacraft"
modpack_version = "1.0.0"
max_players = 100
```

## Running it

```bash
# Run the compiled binary
./target/release/kojacoord-proxy

# Or run directly with Cargo
cargo run --release
```

That's it—you should see the proxy start up and begin accepting connections!

## Supported versions

Client → limbo entry status (each row is end-to-end verified against a real
vanilla client of that version: client reaches the limbo flat-world spawn,
the chat / sound / abilities / keepalive loop holds, and the proxy can
gracefully kick with the configured shutdown reason):

| Version family   | Protocol range | Status                              |
| ---------------- | -------------- | ----------------------------------- |
| 1.6.x            | 73 - 78        | Tested                              |
| 1.7.x            | 4 - 5          | Tested                              |
| 1.8.x            | 47             | Tested                              |
| 1.9.x            | 107 - 110      | WIP                                 |
| 1.10.x           | 210 - 210      | WIP                                 |
| 1.11.x           | 315 - 316      | WIP                                 |
| 1.12.x           | 335 - 340      | Tested                              |
| 1.13.x           | 393 - 404      | Tested                              |
| 1.14.x           | 477 - 498      | Tested                              |
| 1.15.x           | 573 - 578      | Tested                              |
| 1.16.x           | 735 - 754      | Tested                              |
| 1.17.x           | 755 - 756      | Tested                              |
| 1.18.x           | 757 - 758      | Tested                              |
| 1.19.x           | 759 - 762      | WIP                                 |
| 1.20.x           | 763 - 766      | WIP                                 |
| 1.21.x           | 767+           | WIP                                 |

Protocol conversion happens automatically when clients connect to backend
servers running different versions—no manual configuration needed. The
1.6.x ↔ 1.12.2 converter pair (`v1_6_4_to_v1_12_2.rs` /
`v1_12_2_to_v1_6_4.rs`) covers the full gameplay packet set bidirectionally;
the relay framing is pre-netty-aware so 1.6 clients see raw `[id][body]`
bytes while modern backends still get varint-length-framed + compressed
packets.

## API docs

### HTTP API

The proxy exposes a RESTful API for management operations when configured.

#### Authentication

All API requests require an `Authorization` header with your configured token:

```
Authorization: Bearer your-api-token
```

#### Endpoints

- `GET /api/players` - List online players
- `GET /api/players/{uuid}` - Get player details
- `POST /api/players/{uuid}/kick` - Kick a player
- `GET /api/servers` - List backend servers
- `GET /api/metrics` - Get performance metrics
- `GET /api/health` - Health check

## Performance

- **Concurrent Connections**: Handles thousands of simultaneous connections without breaking a sweat
- **Low Latency**: Sub-millisecond proxy overhead—your players won't even notice it's there
- **Memory Efficient**: Optimized buffer pooling and zero-copy where possible
- **Async I/O**: Non-blocking operations using Tokio for maximum throughput

## Security

- RSA encryption for authentication handshakes
- Profile property signature verification (Mojang public key)
- Configurable proxy connection prevention
- PROXY protocol support for real client IPs
- Secure API authentication
- TLS support for database connections

## Contributing

We'd love your help! Here's how to contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code style

- Run `cargo fmt` to format your code
- Use `cargo clippy` for linting
- Write tests for new functionality
- Document public APIs with rustdoc comments

## Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_name
```

## Found a bug?

If you run into an issue, please open a GitHub issue with:

- Proxy version
- Minecraft client version
- Backend server version
- Configuration (redact sensitive info!)
- Error logs
- Steps to reproduce

The more details you give us, the faster we can fix it.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Alex Guy Yann Le Roy

## Thanks

- Built with [Tokio](https://tokio.rs/) for async runtime
- Protocol implementation inspired by other Minecraft proxy projects
- Our amazing community for feedback and contributions

## Protocol Sources

We couldn't have built accurate protocol support without these amazing resources:

- [Minecraft Wiki - Java Edition Protocol](https://minecraft.wiki/w/Java_Edition_protocol/Packets) - Comprehensive packet documentation and version history
- [PrismarineJS minecraft-data](https://github.com/PrismarineJS/minecraft-data) - Detailed protocol data and mappings
- [ProtocolSupport](https://www.javatips.net/api/ProtocolSupportBungee-master/src/protocolsupport/protocol/transformer/v_1_4_1_5_1_6_core/) - For legacy protocols with detailled informations.

Huge thanks to the maintainers of these projects for providing such invaluable information about Minecraft's protocols.

## Get in touch

Have questions? Need support? Want to chat? Open an issue on GitHub or join our Discord.

## What's next?

- [ ] Additional protocol version support
- [x] Plugin system with WASM runtime
- [x] Hot-reload for plugins
- [x] Cluster support for horizontal scaling
- [x] Enhanced metrics and analytics
