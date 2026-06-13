//! Plugin host.
//!
//! Two loaders share one public API ([`api::Plugin`]):
//!   - `wasm_loader` — sandboxed wasmtime, slower but safe to run
//!     unaudited modules
//!   - native `.dll`/`.so`/`.dylib` plugins, fast but unsandboxed and
//!     gated on the SHA-256 allowlist in [`integrity`]
//!
//! [`manager::PluginManager`] is the single owner of all loaded
//! plugins; the proxy holds it inside a `std::sync::RwLock` because
//! every relayed packet takes a read guard for the packet-hook
//! pipeline.

#![deny(clippy::all)]

pub mod api;
pub mod integrity;
pub mod manager;
pub mod native_loader;
pub mod sandbox;
pub mod wasm_loader;

pub use api::{
    CommandSender, PacketData, PacketDirection, PacketEvent, PacketFilter, PacketHookFn,
    PacketHookResult, Plugin, PluginActivity, PluginCommand, PluginCommandSpec, PluginContext,
    PluginEvent, PluginEventKind, PluginMetadata, PluginPermission, PluginResponse, ALL_EVENTS,
};
pub use integrity::PluginVerifier;
pub use manager::PluginManager;
pub use native_loader::PluginLoader;
pub use sandbox::{apply_sandbox, validate_plugin_permissions, SandboxConfig};
pub use wasm_loader::{WasmLoader, WasmPluginAdapter, WasmPluginInstance};
