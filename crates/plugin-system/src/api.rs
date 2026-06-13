//! Public plugin API: the trait every plugin (native or WASM)
//! implements, the event/command/response enums that flow between
//! plugin and host, and the permission set used to gate privileged
//! operations.
//!
//! Plugins can't reach into proxy internals directly — they send
//! [`PluginCommand`]s back through a channel handed to them in
//! [`PluginContext`], and the proxy dispatches the actual side-effect.
//! Same for events: the host fans out [`PluginEvent`]s and collects
//! [`PluginResponse`]s, but only the host gets to act on them.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Commands a plugin can send to the proxy to request privileged operations.
#[derive(Debug, Clone)]
pub enum PluginCommand {
    RegisterServer {
        name: String,
        address: String,
        port: u16,
        max_players: u32,
    },
    DeregisterServer {
        name: String,
    },
    TransferPlayer {
        uuid: Uuid,
        server: String,
    },
    KickPlayer {
        uuid: Uuid,
        reason: String,
    },
    SendSystemMessage {
        uuid: Uuid,
        message: String,
    },
    UpdatePlayerStatus {
        uuid: Uuid,
        server: Option<String>,
        online: bool,
    },
}

pub struct PluginContext {
    pub plugin_id: String,
    pub version: String,
    pub config: HashMap<String, String>,
    /// Channel for sending privileged commands to the proxy. Set by the proxy
    /// when the plugin is loaded.
    pub command_tx: Option<tokio::sync::mpsc::UnboundedSender<PluginCommand>>,
    /// Tokio runtime handle so native plugins can spawn tasks even when loaded
    /// across a dynamic-library boundary where thread-local storage (and thus
    /// the ambient runtime) is not shared. `None` for WASM plugins, which run
    /// inside the host's wasmtime store and never spawn their own tasks.
    pub runtime_handle: Option<tokio::runtime::Handle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginEvent {
    PlayerJoin {
        uuid: Uuid,
        username: String,
    },
    PlayerLeave {
        uuid: Uuid,
    },
    PlayerChat {
        uuid: Uuid,
        message: String,
    },
    PlayerMove {
        uuid: Uuid,
        x: f64,
        y: f64,
        z: f64,
        on_ground: bool,
    },
    ServerMessage {
        message: String,
    },
    Custom {
        event_type: String,
        data: serde_json::Value,
    },
    /// Fired when building the server list ping response.
    /// Plugins can customize the player list and sample data.
    ServerListPing {
        max_players: usize,
        online_players: usize,
        sample: Vec<PlayerSample>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerSample {
    pub name: String,
    pub uuid: Uuid,
}

/// What both native and WASM plugins implement. Lifecycle methods are
/// called in the order `on_load → on_enable … on_disable → on_unload`;
/// `handle_event` runs while the plugin is enabled. `register_packet_hooks`
/// is called once after load to install relay-level filters.
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn author(&self) -> &str;
    fn description(&self) -> &str;

    /// Called once after the binary is verified and instantiated.
    /// Plugins should grab `context.command_tx` here and stash it for
    /// the duration of their life.
    fn on_load(&mut self, context: &PluginContext) -> anyhow::Result<()>;
    /// Mirror of `on_load` — last chance to release resources before
    /// the binary is unmapped. Errors are logged but don't block unload.
    fn on_unload(&mut self) -> anyhow::Result<()>;
    /// Plugin moved from loaded-but-idle to active. Hooks start firing.
    fn on_enable(&mut self) -> anyhow::Result<()>;
    /// Plugin moved from active to idle. Hooks stop firing.
    fn on_disable(&mut self) -> anyhow::Result<()>;

    /// Per-event entry point. Returning `None` is the same as
    /// `Some(PluginResponse::None)` — the host won't act on it.
    fn handle_event(&mut self, event: &PluginEvent) -> anyhow::Result<Option<PluginResponse>>;

    /// Override if the plugin wants relay-level packet hooks. Default
    /// returns an empty list (plugin only sees high-level
    /// `PluginEvent`s).
    fn register_packet_hooks(&mut self) -> Vec<PacketEvent> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginResponse {
    None,
    Message(String),
    KickPlayer {
        uuid: Uuid,
        reason: String,
    },
    Broadcast(String),
    Custom(serde_json::Value),
    /// Cancel the event, preventing further processing and propagation
    Cancel,
    /// Customize the server list ping player sample
    UpdatePlayerSample {
        sample: Vec<PlayerSample>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub min_proxy_version: String,
    pub dependencies: Vec<String>,
    /// Permissions requested by the plugin
    pub permissions: Vec<PluginPermission>,
}

/// Capability flags a plugin's manifest declares; the host enforces
/// these at the point of each privileged operation. Operators can
/// also pass an explicit allowlist via `[plugin_permissions]` in the
/// config — manifest-declared permissions outside that list are
/// dropped silently at load time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginPermission {
    /// Read player information (UUID, username, IP)
    ReadPlayerInfo,
    /// Kick players from the proxy
    KickPlayer,
    /// Send messages to players
    SendMessage,
    /// Broadcast messages to all players
    Broadcast,
    /// Modify packets in transit
    ModifyPackets,
    /// Read packet contents
    ReadPackets,
    /// Access server registry
    AccessServers,
    /// Register new servers dynamically
    RegisterServers,
    /// Access routing rules
    AccessRouting,
    /// Read proxy configuration
    ReadConfig,
    /// Execute commands on behalf of players
    ExecuteCommands,
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
    /// Default priority is 0. Negative values are allowed for low-priority hooks.
    priority: i32,
}

impl PacketEvent {
    pub fn hook(filter: PacketFilter, hook: PacketHookFn) -> Self {
        Self {
            filter,
            hook,
            priority: 0,
        }
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
        }
    }

    /// Hook to a specific serverbound packet
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
        }
    }

    /// Set the priority for this packet hook.
    /// Higher priorities execute first. Default is 0.
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
