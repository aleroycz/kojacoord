//! Wire-level networking layer.
//!
//! `connection` is the per-socket state machine (accept →
//! handshake → login → play handoff); `relay` is the play-phase
//! packet pump; `limbo` is the fake world for offline-backend
//! sessions; the rest cover supporting infrastructure (per-IP
//! throttling, plugin-channel rate limits, packet I/O, modloader
//! detection, the converter framework).

pub mod connection;
pub mod connection_pool;
pub mod connection_throttle;
pub mod converter;
pub mod limbo;
pub mod limbo_packets;
pub mod login_packets;
pub mod modloader;
pub mod packet_builder;
pub mod packet_ids;
pub mod packet_io;
pub mod plugin_channel_rate_limit;
pub mod plugin_decoder;

/// PROXY protocol support for reading real client IPs from upstream load balancers.
pub mod proxy_protocol;
pub mod registry_data;
pub mod relay;
