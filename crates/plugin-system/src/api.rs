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
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Lock-free view of what loaded plugins are interested in, shared
/// directly with the proxy hot path (the per-player relay tasks).
///
/// The relay must NOT take the global `RwLock<PluginManager>` for
/// every packet — under load that single lock's cache line bounces
/// across hundreds of player tasks and any hot-reload write lock
/// stalls movement for everyone (the root cause of the rubber-banding
/// reported in production). Instead the manager folds every loaded
/// plugin's [`Plugin::subscribed_events`] mask and packet-hook count
/// into these atomics, and the relay tests them with a single relaxed
/// load before deciding whether the plugin pipeline is worth a lock at
/// all. When no plugin cares, the hot path pays one atomic read.
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

    /// True if at least one loaded plugin subscribes to `kind`. One
    /// relaxed atomic load — cheap enough for the per-packet hot path.
    #[inline]
    pub fn subscribes(&self, kind: PluginEventKind) -> bool {
        self.event_mask.load(Ordering::Relaxed) & (kind as u32) != 0
    }

    /// True if any relay-level packet hooks are registered.
    #[inline]
    pub fn has_packet_hooks(&self) -> bool {
        self.packet_hooks.load(Ordering::Relaxed) != 0
    }

    /// Replace the event-subscription mask. Called by the manager on
    /// load/unload after recomputing the union over all plugins.
    pub fn set_event_mask(&self, mask: u32) {
        self.event_mask.store(mask, Ordering::Relaxed);
    }

    pub fn set_packet_hook_count(&self, count: usize) {
        self.packet_hooks.store(count, Ordering::Relaxed);
    }
}

/// Bit flags identifying each [`PluginEvent`] variant. Plugins declare
/// which events they want via [`Plugin::subscribed_events`] by OR-ing
/// these together; the host uses the union to gate the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum PluginEventKind {
    PlayerJoin = 1 << 0,
    PlayerLeave = 1 << 1,
    PlayerChat = 1 << 2,
    PlayerMove = 1 << 3,
    ServerMessage = 1 << 4,
    ServerListPing = 1 << 5,
    Custom = 1 << 6,
    PreLogin = 1 << 7,
    PostLogin = 1 << 8,
    ServerConnect = 1 << 9,
    ServerSwitch = 1 << 10,
    ServerKick = 1 << 11,
    ProxyPing = 1 << 12,
    TabComplete = 1 << 13,
    PluginMessage = 1 << 14,
    PermissionCheck = 1 << 15,
}

/// Convenience: subscribe to every event kind. This is the default for
/// plugins that don't narrow their interest, so legacy plugins keep
/// receiving everything.
pub const ALL_EVENTS: u32 = u32::MAX;

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
    /// Customize the limbo world shown to players while no backend is
    /// available. Each field is `None` to leave that aspect at its
    /// built-in default. Plaintext (legacy `§` colour codes allowed);
    /// the proxy wraps it into the right per-version packet.
    SetLimboCustomization {
        /// Chat line sent on limbo entry.
        welcome_message: Option<String>,
        /// Boss-bar title shown while waiting (1.9+ clients).
        bossbar_title: Option<String>,
        /// Spawn coordinates `(x, y, z)` inside limbo.
        spawn: Option<(f64, f64, f64)>,
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
    ///
    /// Native plugins **must** drive all async work through this handle and
    /// **must not** spawn a bare `std::thread` to run runtime-dependent code.
    /// A raw OS thread does not inherit a reactor across the dylib boundary, so
    /// constructing a `tokio::time::interval`, timeout, or any I/O resource on
    /// it panics with *"there is no reactor running"* — and that panic on a
    /// plugin-owned thread is outside the host's `catch_unwind` reach, so it can
    /// take down the whole process. Spawn onto the handle instead:
    ///
    /// ```ignore
    /// // in on_load: stash context.runtime_handle, then in on_enable:
    /// let handle = self.runtime_handle.clone().expect("native plugins get a handle");
    /// handle.spawn(async move {
    ///     let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
    ///     loop { tick.tick().await; /* periodic work */ }
    /// });
    /// ```
    ///
    /// If a plugin genuinely needs its own thread, call `handle.enter()` to put
    /// the runtime in scope before creating any timer or I/O resource.
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

    // --- BungeeCord-parity events -------------------------------------
    /// Before the player is authenticated. Plugins may cancel
    /// ([`PluginResponse::Cancel`]) or kick to deny the connection.
    PreLogin {
        username: String,
        address: String,
    },
    /// After successful login, before the player is sent to a backend.
    PostLogin {
        uuid: Uuid,
        username: String,
    },
    /// Player is about to be connected to a backend server. Plugins may
    /// cancel or redirect (via a [`PluginCommand::TransferPlayer`]).
    ServerConnect {
        uuid: Uuid,
        target: String,
    },
    /// Player has finished switching from one backend to another.
    ServerSwitch {
        uuid: Uuid,
        from: Option<String>,
        to: String,
    },
    /// A backend kicked the player. Plugins may suppress the kick or
    /// reroute the player elsewhere (e.g. fall back to the hub).
    ServerKick {
        uuid: Uuid,
        server: String,
        reason: String,
    },
    /// Player disconnected from the proxy entirely.
    PlayerDisconnect {
        uuid: Uuid,
        username: String,
    },
    /// A tab-completion request from the client.
    TabComplete {
        uuid: Uuid,
        input: String,
    },
    /// A custom plugin-channel message arrived from a backend or client.
    PluginMessage {
        uuid: Uuid,
        channel: String,
        data: Vec<u8>,
    },
    /// A permission check is being resolved for a player. Plugins (e.g.
    /// a LuckPerms port) may answer authoritatively via
    /// [`PluginResponse::PermissionResult`].
    PermissionCheck {
        uuid: Uuid,
        node: String,
    },
}

impl PluginEvent {
    /// The bit flag identifying this event's variant, used for
    /// subscription gating on the hot path.
    pub fn kind(&self) -> PluginEventKind {
        match self {
            PluginEvent::PlayerJoin { .. } => PluginEventKind::PlayerJoin,
            PluginEvent::PlayerLeave { .. } => PluginEventKind::PlayerLeave,
            PluginEvent::PlayerChat { .. } => PluginEventKind::PlayerChat,
            PluginEvent::PlayerMove { .. } => PluginEventKind::PlayerMove,
            PluginEvent::ServerMessage { .. } => PluginEventKind::ServerMessage,
            PluginEvent::ServerListPing { .. } => PluginEventKind::ServerListPing,
            PluginEvent::Custom { .. } => PluginEventKind::Custom,
            PluginEvent::PreLogin { .. } => PluginEventKind::PreLogin,
            PluginEvent::PostLogin { .. } => PluginEventKind::PostLogin,
            PluginEvent::ServerConnect { .. } => PluginEventKind::ServerConnect,
            PluginEvent::ServerSwitch { .. } => PluginEventKind::ServerSwitch,
            PluginEvent::ServerKick { .. } => PluginEventKind::ServerKick,
            PluginEvent::PlayerDisconnect { .. } => PluginEventKind::PlayerLeave,
            PluginEvent::TabComplete { .. } => PluginEventKind::TabComplete,
            PluginEvent::PluginMessage { .. } => PluginEventKind::PluginMessage,
            PluginEvent::PermissionCheck { .. } => PluginEventKind::PermissionCheck,
        }
    }
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

    /// Bit mask (OR of [`PluginEventKind`] values) of the events this
    /// plugin wants delivered. The host folds every plugin's mask into
    /// a [`PluginActivity`] so the relay hot path can skip dispatch
    /// entirely when no plugin is listening. Defaults to [`ALL_EVENTS`]
    /// so plugins that don't override keep receiving everything.
    fn subscribed_events(&self) -> u32 {
        ALL_EVENTS
    }

    /// Commands the plugin registers with the proxy's command
    /// dispatcher. Called once after enable. Default: no commands.
    fn register_commands(&mut self) -> Vec<PluginCommandSpec> {
        Vec::new()
    }

    /// Invoked when one of this plugin's registered commands is run.
    /// `args` excludes the command label itself. Default: no-op.
    fn handle_command(
        &mut self,
        _label: &str,
        _args: &[String],
        _sender: &CommandSender,
    ) -> anyhow::Result<Option<PluginResponse>> {
        Ok(None)
    }

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
    /// Authoritative answer to a [`PluginEvent::PermissionCheck`]. A
    /// LuckPerms-style plugin returns this to grant/deny a node; `None`
    /// from every plugin means "no opinion, fall back to roles".
    PermissionResult {
        node: String,
        granted: bool,
    },
}

/// Declarative description of a command a plugin registers with the
/// proxy's dispatcher. Mirrors BungeeCord's `Command`: a primary label,
/// optional aliases, and a permission node gating execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCommandSpec {
    /// Primary label, without the leading slash (e.g. `"fly"`).
    pub label: String,
    /// Alternative labels that dispatch to the same handler.
    pub aliases: Vec<String>,
    /// Permission node required to run, or `None` for everyone.
    pub permission: Option<String>,
    /// One-line help string shown in command listings.
    pub description: String,
}

impl PluginCommandSpec {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            aliases: Vec::new(),
            permission: None,
            description: String::new(),
        }
    }

    pub fn alias(mut self, alias: impl Into<String>) -> Self {
        self.aliases.push(alias.into());
        self
    }

    pub fn permission(mut self, node: impl Into<String>) -> Self {
        self.permission = Some(node.into());
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// Who ran a command. Plugins use this to resolve permissions and to
/// reply. The console sender has no UUID and is granted every node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSender {
    /// `None` for the console.
    pub uuid: Option<Uuid>,
    pub name: String,
    /// Permission nodes the proxy has already resolved for this sender,
    /// so the plugin can gate sub-commands without a round trip.
    pub permissions: Vec<String>,
    pub is_console: bool,
}

impl CommandSender {
    /// True if the sender holds `node` (console holds everything).
    pub fn has_permission(&self, node: &str) -> bool {
        self.is_console || self.permissions.iter().any(|p| p == "*" || p == node)
    }
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
