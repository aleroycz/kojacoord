//! Core proxy implementation.
//!
//! Organised by concern:
//!   - `proxy` — long-lived state, accept loop, background workers
//!   - `net::*` — wire-level handling (connection lifecycle, relay,
//!     limbo, packet I/O, converters, modloader detection)
//!   - `protocol::*` — wiki-versioned dispatch tables and coverage
//!   - `features::*` — exploit guard, commands, etc.
//!   - `services::*` — HTTP API, server-management TCP, telemetry
//!   - `data::*` — DB layer and persisted models
//!
//! Everything user-facing lives in `proxy`; the rest are leaves of
//! that tree.

pub mod buffer_pool;
pub mod chat_signing;
pub mod config_synthesis;
pub mod cookies_transfers;
pub mod crash_report;
pub mod error;
pub mod failover;
pub mod health_probe;
pub mod metrics;
pub mod metrics_player;
pub mod metrics_report;
pub mod proxy;
pub mod realms;
pub mod region_selector;
pub mod resource_pack;
pub mod routing;
pub mod server;
pub mod session;
pub mod telemetry;
pub mod version_check;

pub mod control_plane;
pub mod data;
pub mod features;
pub mod net;
pub mod protocol;
pub mod security;
pub mod services;

pub use control_plane::{ControlPlaneConfig, ControlPlaneServer, ControlPlaneState};
pub use data::{db, permissions};
pub use features::{commands, exploit_guard, server_selector, transfer};
pub use net::{
    connection, connection_pool, connection_throttle, converter, limbo, limbo_packets,
    login_packets, modloader, packet_builder, packet_ids, packet_io, plugin_decoder, relay,
};
pub use protocol::{
    ConverterBuilder, ConverterInfo, CoverageStatus, ProtocolCoverage, VersionPair,
};
pub use security::{EncryptionAlgorithm, EncryptionKey, EncryptionManager};
pub use services::{http_api, server_management};

pub use proxy::{accept_loop, ProxyState};
pub use services::server_management::ServerManagementServer;
