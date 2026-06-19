# Kojacoord Proxy

<div align="center">

[![Website](https://img.shields.io/badge/website-kojacraft.net-blue?style=for-the-badge)](https://www.kojacraft.net)
[![Discord](https://img.shields.io/badge/discord-join-purple?style=for-the-badge&logo=discord)](https://discord.gg/Xp6wFH3nM6)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Crates.io](https://img.shields.io/crates/v/kojacoord-proxy)](https://crates.io/crates/kojacoord-proxy)
[![Documentation](https://img.shields.io/badge/docs.rs-kojacoord--proxy-blue)](https://docs.rs/kojacoord-proxy)

</div>

Kojacoord is a multi-version Minecraft proxy written in Rust. It sits between
Java Edition clients and one or more backend servers, handling the handshake,
authentication, encryption and protocol translation so that clients on a range
of versions can connect to the same network. It is built on the Tokio async
runtime and powers the [KojaCraft](https://www.kojacraft.net) network.

> **Project status.** Kojacoord is under active development. Protocol coverage
> is broad but verification depth varies by version (see
> [Version support](#version-support)). Treat anything marked *WIP* as
> incomplete rather than production-ready, and read each feature's description
> for its real scope.

## Contents

- [What it does](#what-it-does)
- [Feature overview](#feature-overview)
- [Architecture](#architecture)
- [Building](#building)
- [Configuration](#configuration)
- [Running](#running)
- [Version support](#version-support)
- [HTTP API](#http-api)
- [Plugins](#plugins)
- [Security model](#security-model)
- [Contributing](#contributing)
- [License](#license)
- [Protocol sources](#protocol-sources)

## What it does

A client connects to Kojacoord as if it were a normal Minecraft server.
Kojacoord performs the status/login handshake, optionally authenticates the
player against Mojang's session servers, negotiates encryption and compression,
then opens a connection to a backend server and relays packets between the two.

Because clients and backends may run different protocol versions, Kojacoord can
translate packets between version families as it relays them. When no backend
is reachable, players can be held in a built-in *limbo* world instead of being
disconnected.

## Feature overview

Each item below corresponds to functionality present in the codebase. Where a
feature is partial or experimental, that is stated explicitly.

- **Multi-version protocol support.** Handles Minecraft 1.6.x through the
  current 1.21.x line, mapping each client onto a canonical protocol bucket.
  Coverage and verification status vary per version — see
  [Version support](#version-support).
- **Authentication.** Online mode (Mojang session server,
  `hasJoined`-based verification with RSA key exchange) and offline mode.
  Profile property signatures are verified against the configured Mojang public
  key.
- **Player-info forwarding.** Three modes: `none`, `velocity` (modern,
  HMAC-signed) and `bungeecord` (legacy, unsigned). Velocity forwarding
  requires a shared secret; configuration validation rejects weak or missing
  secrets and warns loudly when legacy BungeeCord forwarding is selected.
- **Limbo.** A synthetic flat world that holds players when their backend is
  unavailable rather than kicking them. It synthesises the join, position,
  abilities and keep-alive packets per protocol family and polls for the
  backend to return. Registry handling differs by protocol era (see the note in
  [Version support](#version-support)).
- **Rule-based routing.** Route players by username (case-insensitive glob with
  `*` wildcards) or by client IP (IPv4/IPv6 CIDR). Rules are evaluated in order;
  first match wins, falling back to a default server.
- **Region selector.** Optional routing toward the closest server region using
  an IPv4 heuristic, preferring the least-loaded server in the chosen region and
  falling back to other regions when needed.
- **Failover groups.** Active/standby backend redundancy: a health monitor moves
  traffic from a primary to the first healthy standby, with optional automatic
  failback once the primary recovers.
- **Health probes.** Per-server TCP health checks with configurable interval,
  timeout and failure threshold.
- **Resource packs.** Optionally push a resource pack (URL + SHA-1 hash) to
  clients, with a configurable prompt and required/optional enforcement.
- **PROXY protocol.** Optional HAProxy PROXY protocol v1/v2 support to recover
  the real client IP behind a load balancer, with an optional mode for mixed
  direct/proxied traffic and a trusted-proxy allowlist.
- **Connection throttling.** Per-source-IP new-connection rate limiting with a
  configurable threshold.
- **Plugins.** A WASM-based plugin system with a typed guest SDK, host imports
  (logging, config, commands, permissions, Redis, HTTP), an event model and
  optional polling hot-reload. See [Plugins](#plugins).
- **Clustering.** Redis-backed cluster coordination for running multiple proxy
  nodes (opt-in).
- **Mojang Realms bridge.** Experimental support for exposing a Realm as a named
  backend by authenticating to the Realms API and performing a real online-mode
  login. Self-contained and not enabled by default.
- **Control planes.** An HTTP management/dashboard API, an optional TCP
  server-management control plane, and an optional gRPC control plane for
  external orchestration. All are authenticated and the latter two are opt-in.
- **Operational tooling.** Hot config reload (file watch + `SIGHUP` on Unix),
  gzip log rotation, a panic-hook crash reporter that writes a redacted,
  secret-free report under `logs/`, graceful shutdown that disconnects players
  with a configured reason, and a Prometheus metrics endpoint.
- **Telemetry.** Anonymous, opt-out usage telemetry (coarse, non-identifying
  metrics). Set `telemetry.enabled = false` to disable it entirely; the endpoint
  is then never contacted. See [Security model](#security-model).

## Architecture

The workspace is split into focused crates:

| Crate | Responsibility |
| ----- | -------------- |
| `kojacoord-protocol` | Packet types, codecs and per-version registries |
| `kojacoord-netty` | Framing, compression and encryption codec layer |
| `kojacoord-auth` | Session authentication and login-phase encryption |
| `kojacoord-proxy-core` | Core proxy: sessions, relay, routing, limbo, realms, control planes |
| `kojacoord-config` | Configuration schema, loading and validation |
| `kojacoord-api` | Public API surface for plugin development |
| `kojacoord-plugin-abi` | Wire types shared by the plugin host and guest SDK |
| `kojacoord-plugin-sdk` | Guest SDK for writing WASM plugins |
| `kojacoord-plugin-system` | Plugin loading, lifecycle and host API |
| `kojacoord-cluster` | Redis-backed cluster coordination |
| `kojacoord-metrics` | Prometheus metrics collection and exporter |

## Building

### Requirements

- Rust 1.75 or later (and Cargo)
- `protoc` (Protocol Buffers compiler) — required to build the gRPC control plane
- MySQL — optional; only needed if you use the MySQL database backend instead of
  the default SQLite file

### Compile

```bash
git clone https://github.com/aleroycz/kojacoord.git
cd kojacoord-proxy-experimentals

# Release build (recommended for running the proxy)
cargo build --release
# Binary: target/release/kojacoord-proxy

# Development build + tests
cargo build
cargo test
```

## Configuration

On first run, if no config file is found, Kojacoord writes a default
`config.toml`, generates strong random tokens for any enabled control plane,
and prompts once to accept the Minecraft EULA. You can also pass a config path
as the first argument: `kojacoord-proxy /path/to/config.toml`.

Secrets can be supplied via environment variables instead of the file, using a
`KOJA_` prefix and `__` for nesting — for example
`KOJA_HTTP_API__AUTH_TOKEN`, `KOJA_FORWARDING__VELOCITY_SECRET`,
`KOJA_DATABASE__URL`.

A minimal `config.toml`:

```toml
[proxy]
bind = "0.0.0.0:25565"
online_mode = true
compression_threshold = 256
max_players = 1000
session_timeout_secs = 5

[listeners]
motd = "KojacoordNetwork"
tab_list = "GLOBAL_PING"     # GLOBAL_PING | SERVER_PING | HIDDEN

[forwarding]
mode = "none"                # none | velocity | bungeecord
velocity_secret = ""         # required for velocity; e.g. `openssl rand -hex 32`

[database]
url = ""                     # empty = SQLite at data/proxy.db; or mysql://user:pass@host/db
max_connections = 10

[http_api]
enabled = true
bind = "127.0.0.1:8081"
auth_token = ""              # auto-generated on first run if empty

[telemetry]
enabled = true               # set false to disable usage telemetry entirely
interval_secs = 1800

[[servers]]
name = "lobby"
address = "127.0.0.1:25566"
display_name = "Lobby"
game_type = "lobby"

[[servers]]
name = "survival"
address = "127.0.0.1:25567"
backend_type = "spigot"      # spigot | forge | hybrid
display_name = "Survival"
max_players = 100
```

Many fields hot-reload when the config file changes; others require a restart.
Field-level comments in the generated default config note which is which.

## Running

```bash
# Run the release binary
./target/release/kojacoord-proxy

# Or via Cargo
cargo run --release
```

Configuration changes are picked up automatically on file save, or on `SIGHUP`
(Unix). Press Ctrl+C (or send `SIGTERM`/`SIGQUIT`) for a graceful shutdown that
disconnects players with a configured reason.

## Version support

Every client version is mapped onto a **canonical bucket** — the concrete
typed-packet implementation that drives limbo and protocol conversion for that
protocol family. Several patch releases share one protocol number (e.g. 1.19.1
and 1.19.2 are both protocol 760), so they collapse onto a single row.

The status column reflects how thoroughly each bucket has been verified
end-to-end against a real vanilla client (client reaches the limbo spawn; the
chat/sound/abilities/keep-alive loop holds; the proxy can gracefully disconnect
with the configured reason).

| Version family | Canonical bucket | Status |
| -------------- | ---------------- | ------ |
| 1.6.x          | `V1_6_4`         | Tested |
| 1.7.x          | `V1_7_10`        | Tested |
| 1.8.x          | `V1_8`           | Tested |
| 1.9.x – 1.12.x | `V1_12_2`        | 1.12 tested · 1.9–1.11 tested |
| 1.13.x – 1.16.x| `V1_16_5`        | Tested |
| 1.17.x – 1.19.x| `V1_19_4`        | Tested |
| 1.20.x         | `V1_20_4`        | 1.20 / 1.20.1 tested · 1.20.2+ tested |
| 1.21.x         | `V1_21`          | Tested |
| 1.26.x         | `V26`            | Tested |

> **Limbo registry handling by protocol era.** Protocols ≤ 763 (1.16–1.20.1)
> embed the registry codec directly in the join packet. 1.20.2–1.20.4 (764/765)
> fall back to the client's built-in registries, while 1.20.5+/1.21 (766+) are
> sent explicit `RegistryData` captured from `minecraft-data`. Void-chunk +
> set-center-chunk handling (to clear the "Loading terrain" screen) currently
> covers the `V1_19_4` bucket; the `V1_20`/`V1_21` buckets are being extended.

Protocol conversion between client and backend versions happens automatically
during relay. The 1.6.x ↔ 1.12.2 converter pair covers the gameplay packet set
bidirectionally, and the relay framing is pre-netty-aware so 1.6 clients receive
raw `[id][body]` packets while modern backends receive varint-length-framed,
compressed packets.

The public roadmap (including in-progress work such as Bedrock bridging and a
Realms compatibility layer) lives in [`ROADMAP.md`](ROADMAP.md).

## HTTP API

When `http_api.enabled = true`, Kojacoord exposes an authenticated HTTP API and
serves the management dashboard. All `/api/*` requests require a bearer token:

```
Authorization: Bearer <http_api.auth_token>
```

| Method | Path | Description |
| ------ | ---- | ----------- |
| `GET`  | `/health`        | Health check (DB status, backend and player counts) |
| `GET`  | `/api/players`   | List online players |
| `POST` | `/api/ban`       | Ban a player |
| `POST` | `/api/warn`      | Warn a player |
| `POST` | `/api/mute`      | Mute a player |
| `POST` | `/api/unmute`    | Unmute a player |
| `POST` | `/api/purchase`  | Record/apply a purchase |
| `GET`  | `/`              | Management dashboard |

A Prometheus metrics endpoint is available separately when `metrics.enabled =
true` (default bind `127.0.0.1:9090`).

## Plugins

Plugins are WebAssembly modules. Authors depend on `kojacoord-plugin-sdk` plus
`kojacoord-plugin-abi`, implement the `Plugin` trait, and call `export_plugin!`
once; the macro emits the C ABI exports the host expects and handles JSON
marshalling.

Host services exposed to plugins include logging, config access, sending
commands to the proxy (register/deregister servers, transfer/kick players,
broadcast, mute/ban/warn), permission checks, a Redis client family, and
outbound HTTP. Plugins subscribe to a bitmask of events — player join/leave,
chat, move, server connect/switch/kick, server-list ping, plugin messages,
Redis messages, and more.

```rust
use kojacoord_plugin_sdk::*;

struct MyPlugin;

impl Plugin for MyPlugin {
    fn on_enable(&mut self) {
        log(LogLevel::Info, "hello from wasm");
        redis_connect(&get_config("redis_url").unwrap_or_default());
        redis_subscribe("kojacoord:sanctions");
    }

    fn handle_event(&mut self, ev: &PluginEvent) -> Option<PluginResponse> {
        if let PluginEvent::RedisMessage { channel, payload } = ev {
            log(LogLevel::Info, &format!("{channel}: {payload}"));
        }
        None
    }
}

export_plugin!(MyPlugin, MyPlugin);
```

With `plugins.hot_reload = true`, the plugin directory is polled and modules are
reloaded when their file changes.

## Security model

- **Login encryption.** Online-mode login uses RSA key exchange followed by
  AES-CFB8 packet encryption, as per the vanilla protocol.
- **Identity verification.** Profile property signatures are verified against
  the configured Mojang public key.
- **Forwarding secrets.** Velocity forwarding is HMAC-signed and validated at
  startup. Legacy BungeeCord forwarding is unsigned by design — backends must be
  firewalled to accept connections only from the proxy. Startup validation
  rejects empty, too-short, or well-known placeholder secrets for any enabled
  control plane.
- **Control-plane internode encryption.** A pluggable cipher registry (separate
  from Minecraft login encryption) provides AES-256-GCM, ChaCha20-Poly1305 and
  XChaCha20-Poly1305 for internode/control-plane payloads, with support for
  registering custom algorithms. An optional post-quantum cipher
  (`post-quantum` cargo feature) implements a real ML-KEM-768 (NIST FIPS 203) +
  AES-256-GCM KEM-DEM hybrid via the RustCrypto `ml-kem` crate. It is off by
  default and is a KEM+DEM hybrid only — not combined with a classical KEM — so
  pair it with a classical cipher if you need classical/PQ hybrid guarantees.
- **Crash reports.** Crash reports are IP-redacted and exclude tokens, the
  database URL and keys, so they are safe to share when filing a bug.

## Contributing

1. Fork the repository and create a feature branch.
2. Make your change, keeping it consistent with the surrounding code.
3. Run `cargo fmt`, `cargo clippy` and `cargo test`.
4. Add tests for new functionality and rustdoc for public APIs.
5. Open a pull request describing the change and its motivation.

When reporting a bug, please include the proxy version, the client and backend
versions, a redacted config, relevant log output, and steps to reproduce.

## License

Licensed under the MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 Alex Guy Yann Le Roy.

## Protocol sources

Protocol support is built against these references:

- [Minecraft Wiki — Java Edition protocol](https://minecraft.wiki/w/Java_Edition_protocol/Packets) — packet documentation and version history
- [PrismarineJS minecraft-data](https://github.com/PrismarineJS/minecraft-data) — protocol data and mappings
- [ProtocolSupport](https://github.com/ProtocolSupport/ProtocolSupport) — reference for legacy protocols
</content>
</invoke>
