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

/// Run a closure that calls into (possibly native) plugin code, converting a
/// panic that unwinds out of the plugin into an `Err` instead of letting it
/// escape.
///
/// A native plugin runs with full process privileges in the host's address
/// space. When one panics inside a hook the host invokes synchronously
/// (`on_load`, `on_enable`, `handle_event`, a packet hook, …) the unwind would
/// otherwise tear through host frames — and across the `extern "C"` entry
/// points that is undefined behaviour that in practice aborts or segfaults the
/// whole proxy. Catching here lets a buggy or malicious plugin take only
/// itself down.
///
/// Limitation: this can only contain panics on the calling thread. A panic on
/// a thread the plugin spawns itself (e.g. a bare `std::thread` running a
/// `tokio::time::interval` with no reactor) terminates that thread out of our
/// reach — the fix for that lives in the plugin, which must use
/// [`PluginContext::runtime_handle`](api::PluginContext) rather than its own
/// ungoverned thread.
pub(crate) fn guard_plugin_call<T>(what: &str, f: impl FnOnce() -> T) -> anyhow::Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|payload| {
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_string()
        };
        log::error!("plugin panicked during {what}: {msg}");
        anyhow::anyhow!("plugin panicked during {what}: {msg}")
    })
}
