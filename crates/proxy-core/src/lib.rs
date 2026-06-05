#![deny(clippy::all)]

pub mod buffer_pool;
pub mod error;
pub mod metrics;
pub mod proxy;
pub mod routing;
pub mod server;
pub mod session;
pub mod telemetry;

pub mod data;
pub mod features;
pub mod net;
pub mod services;

pub use data::{db, permissions};
pub use features::{commands, exploit_guard, server_selector, transfer};
pub use net::{
    connection, connection_pool, connection_throttle, converter, limbo, modloader, packet_builder,
    packet_ids, packet_io, plugin_decoder, relay,
};
pub use services::{http_api, server_management};

pub use proxy::{accept_loop, ProxyState};
pub use services::server_management::ServerManagementServer;
