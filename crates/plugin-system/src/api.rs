//! Public plugin API (host side).
//!
//! The JSON wire types (events, commands, responses, manifest) live in
//! [`kojacoord_plugin_abi`] so the WASM guest SDK can share them verbatim;
//! they are re-exported here so existing `kojacoord_plugin_system::…`
//! imports keep working. This module adds the host-only pieces: the
//! [`Plugin`] trait, [`PluginContext`] (carries the tokio handle and
//! command channel), the lock-free [`PluginActivity`] snapshot, and the
//! relay-level packet-hook types.

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

// Re-export every wire type from the shared ABI crate so downstream code
// (and this crate) can keep referring to `kojacoord_plugin_system::…`.
pub use kojacoord_plugin_abi::{
    permission_name, CommandSender, PlayerSample, PluginCommand, PluginCommandSpec, PluginEvent,
    PluginEventKind, PluginMetadata, PluginPermission, PluginResponse, ALL_EVENTS,
};

/// Lock-free view of what loaded plugins are interested in, shared
/// directly with the proxy hot path (the per-player relay tasks).
#[derive(Debug, Default)]
pub struct PluginActivity {
    /// OR of every loaded plugin's [`Plugin::subscribed_events`] mask.
    event_mask: AtomicU32,
    /// Number of registered relay-level packet hooks.
    packet_hooks: AtomicUsize,
}

impl PluginActivity {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// True if at least one loaded plugin subscribes to `kind`.
    #[inline]
    pub fn subscribes(&self, kind: PluginEventKind) -> bool {
        self.event_mask.load(Ordering::Relaxed) & (kind as u32) != 0
    }

    /// True if any relay-level packet hooks are registered.
    #[inline]
    pub fn has_packet_hooks(&self) -> bool {
        self.packet_hooks.load(Ordering::Relaxed) != 0
    }

    /// Replace the event-subscription mask.
    pub fn set_event_mask(&self, mask: u32) {
        self.event_mask.store(mask, Ordering::Relaxed);
    }

    pub fn set_packet_hook_count(&self, count: usize) {
        self.packet_hooks.store(count, Ordering::Relaxed);
    }
}

pub struct PluginContext {
    pub plugin_id: String,
    pub version: String,
    pub config: HashMap<String, String>,
    /// Channel for sending privileged commands to the proxy.
    pub command_tx: Option<tokio::sync::mpsc::UnboundedSender<PluginCommand>>,
    /// Tokio runtime handle so plugins can drive async work (native plugins
    /// spawn tasks; the WASM loader uses it to run Redis/HTTP host imports).
    pub runtime_handle: Option<tokio::runtime::Handle>,
}

/// What both native and WASM plugins implement (host-side trait). The WASM
/// adapter forwards each method across the wasm boundary.
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn author(&self) -> &str;
    fn description(&self) -> &str;

    fn on_load(&mut self, context: &PluginContext) -> anyhow::Result<()>;
    fn on_unload(&mut self) -> anyhow::Result<()>;
    fn on_enable(&mut self) -> anyhow::Result<()>;
    fn on_disable(&mut self) -> anyhow::Result<()>;

    fn handle_event(&mut self, event: &PluginEvent) -> anyhow::Result<Option<PluginResponse>>;

    /// Bit mask (OR of [`PluginEventKind`] values) of the events this
    /// plugin wants delivered. Defaults to [`ALL_EVENTS`].
    fn subscribed_events(&self) -> u32 {
        ALL_EVENTS
    }

    /// Commands the plugin registers with the proxy's command dispatcher.
    fn register_commands(&mut self) -> Vec<PluginCommandSpec> {
        Vec::new()
    }

    /// Invoked when one of this plugin's registered commands is run.
    fn handle_command(
        &mut self,
        _label: &str,
        _args: &[String],
        _sender: &CommandSender,
    ) -> anyhow::Result<Option<PluginResponse>> {
        Ok(None)
    }

    /// Override if the plugin wants relay-level packet hooks.
    fn register_packet_hooks(&mut self) -> Vec<PacketEvent> {
        Vec::new()
    }

    /// Drain any Redis subscribe messages the host has queued for this
    /// plugin since the last call, as `(channel, payload)` pairs. WASM
    /// plugins use this (the host pumps the results back in as
    /// [`PluginEvent::RedisMessage`]); the default is empty.
    fn drain_redis_messages(&mut self) -> Vec<(String, String)> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Clientbound,
    Serverbound,
}

#[derive(Debug, Clone)]
pub struct PacketFilter {
    pub protocol_version: Option<u32>,
    pub packet_id: Option<i32>,
    pub direction: PacketDirection,
}

impl PacketFilter {
    pub fn new(direction: PacketDirection) -> Self {
        Self {
            protocol_version: None,
            packet_id: None,
            direction,
        }
    }

    pub fn with_protocol_version(mut self, version: u32) -> Self {
        self.protocol_version = Some(version);
        self
    }

    pub fn with_packet_id(mut self, id: i32) -> Self {
        self.packet_id = Some(id);
        self
    }
}

#[derive(Debug, Clone)]
pub struct PacketData {
    pub protocol_version: u32,
    pub packet_id: i32,
    pub direction: PacketDirection,
    pub data: Bytes,
    pub player_uuid: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub enum PacketHookResult {
    Forward,
    Drop,
    Modify(Bytes),
    Replace { packet_id: i32, data: Bytes },
}

pub type PacketHookFn = Box<dyn Fn(&PacketData) -> anyhow::Result<PacketHookResult> + Send + Sync>;

pub struct PacketEvent {
    filter: PacketFilter,
    hook: PacketHookFn,
    /// Priority determines execution order: higher values execute first.
    priority: i32,
    pub plugin_name: String,
}

impl PacketEvent {
    pub fn hook(filter: PacketFilter, hook: PacketHookFn) -> Self {
        Self {
            filter,
            hook,
            priority: 0,
            plugin_name: String::new(),
        }
    }

    pub fn with_plugin_name(mut self, name: impl Into<String>) -> Self {
        self.plugin_name = name.into();
        self
    }

    pub fn hook_to_clientbound<F>(
        protocol_version: Option<u32>,
        packet_id: Option<i32>,
        hook: F,
    ) -> Self
    where
        F: Fn(&PacketData) -> anyhow::Result<PacketHookResult> + Send + Sync + 'static,
    {
        let filter = PacketFilter {
            protocol_version,
            packet_id,
            direction: PacketDirection::Clientbound,
        };
        Self {
            filter,
            hook: Box::new(hook),
            priority: 0,
            plugin_name: String::new(),
        }
    }

    pub fn hook_to_serverbound<F>(
        protocol_version: Option<u32>,
        packet_id: Option<i32>,
        hook: F,
    ) -> Self
    where
        F: Fn(&PacketData) -> anyhow::Result<PacketHookResult> + Send + Sync + 'static,
    {
        let filter = PacketFilter {
            protocol_version,
            packet_id,
            direction: PacketDirection::Serverbound,
        };
        Self {
            filter,
            hook: Box::new(hook),
            priority: 0,
            plugin_name: String::new(),
        }
    }

    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    pub fn matches(&self, packet: &PacketData) -> bool {
        if packet.direction != self.filter.direction {
            return false;
        }
        if let Some(version) = self.filter.protocol_version {
            if packet.protocol_version != version {
                return false;
            }
        }
        if let Some(id) = self.filter.packet_id {
            if packet.packet_id != id {
                return false;
            }
        }
        true
    }

    pub fn execute(&self, packet: &PacketData) -> anyhow::Result<PacketHookResult> {
        (self.hook)(packet)
    }

    pub fn filter(&self) -> &PacketFilter {
        &self.filter
    }

    pub fn priority(&self) -> i32 {
        self.priority
    }
}
