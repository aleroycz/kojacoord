//! Plugin wire types shared between the host ([`kojacoord-plugin-system`])
//! and the WASM guest SDK ([`kojacoord-plugin-sdk`]).
//!
//! These are the JSON-serializable types that cross the host/guest
//! boundary: events the host fans out, commands the guest sends back, the
//! responses to events, and the manifest/permission model. They live in
//! their own crate (no tokio / wasmtime / bytes) so a guest compiled to
//! `wasm32-wasip1` can depend on the exact same definitions the host uses,
//! eliminating drift in the JSON contract.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Bit flags identifying each [`PluginEvent`] variant. Plugins declare
/// which events they want by OR-ing these together; the host uses the
/// union to gate the hot path.
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
    /// Player finished connecting to a backend (BungeeCord `ServerConnectedEvent`).
    ServerConnected = 1 << 16,
    /// Client settings changed (BungeeCord `SettingsChangedEvent`).
    SettingsChanged = 1 << 17,
    /// Player was disconnected from the proxy.
    PlayerDisconnect = 1 << 18,
    /// A message arrived on a Redis channel the plugin subscribed to.
    RedisMessage = 1 << 19,
}

/// Convenience: subscribe to every event kind.
pub const ALL_EVENTS: u32 = u32::MAX;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerSample {
    pub name: String,
    pub uuid: Uuid,
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
    ServerListPing {
        max_players: usize,
        online_players: usize,
        sample: Vec<PlayerSample>,
    },

    // --- BungeeCord-parity events -------------------------------------
    /// Before the player is authenticated. Plugins may cancel or kick.
    PreLogin {
        username: String,
        address: String,
    },
    /// After successful login, before the player is sent to a backend.
    PostLogin {
        uuid: Uuid,
        username: String,
    },
    /// Player is about to be connected to a backend server.
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
    /// A backend kicked the player.
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
    /// Player finished connecting to a backend (post-connect; BungeeCord
    /// `ServerConnectedEvent`).
    ServerConnected {
        uuid: Uuid,
        server: String,
    },
    /// The client's settings changed (locale, render/view distance).
    SettingsChanged {
        uuid: Uuid,
        locale: Option<String>,
        view_distance: Option<u8>,
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
    /// A permission check is being resolved for a player.
    PermissionCheck {
        uuid: Uuid,
        node: String,
    },
    /// A message arrived on a Redis channel the plugin subscribed to via
    /// the `redis_subscribe` host import.
    RedisMessage {
        channel: String,
        payload: String,
    },
}

impl PluginEvent {
    /// The bit flag identifying this event's variant.
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
            PluginEvent::PlayerDisconnect { .. } => PluginEventKind::PlayerDisconnect,
            PluginEvent::ServerConnected { .. } => PluginEventKind::ServerConnected,
            PluginEvent::SettingsChanged { .. } => PluginEventKind::SettingsChanged,
            PluginEvent::TabComplete { .. } => PluginEventKind::TabComplete,
            PluginEvent::PluginMessage { .. } => PluginEventKind::PluginMessage,
            PluginEvent::PermissionCheck { .. } => PluginEventKind::PermissionCheck,
            PluginEvent::RedisMessage { .. } => PluginEventKind::RedisMessage,
        }
    }
}

/// Commands a plugin can send to the proxy to request privileged operations.
///
/// `Serialize`/`Deserialize` so WASM guests can emit commands as JSON over
/// the host `send_command` import.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Broadcast a system chat line to every online player.
    BroadcastMessage {
        message: String,
    },
    /// Mute a player's chat. `duration_secs` is `None` (or `<= 0`) for a
    /// permanent mute.
    MutePlayer {
        uuid: Uuid,
        reason: String,
        duration_secs: Option<i64>,
    },
    /// Lift a player's mute (DB + live session).
    UnmutePlayer {
        uuid: Uuid,
    },
    /// Ban a player. `duration_secs` is `None` (or `<= 0`) for a permanent ban.
    BanPlayer {
        uuid: Uuid,
        reason: String,
        duration_secs: Option<i64>,
    },
    /// Record a warning against a player and, if online, deliver the reason.
    WarnPlayer {
        uuid: Uuid,
        reason: String,
    },
    UpdatePlayerStatus {
        uuid: Uuid,
        server: Option<String>,
        online: bool,
    },
    /// Customize the limbo world shown to players while no backend is
    /// available. Each field is `None` to leave that aspect at its default.
    SetLimboCustomization {
        welcome_message: Option<String>,
        bossbar_title: Option<String>,
        spawn: Option<(f64, f64, f64)>,
    },
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
    /// Cancel the event, preventing further processing and propagation.
    Cancel,
    /// Customize the server list ping player sample.
    UpdatePlayerSample {
        sample: Vec<PlayerSample>,
    },
    /// Authoritative answer to a [`PluginEvent::PermissionCheck`].
    PermissionResult {
        node: String,
        granted: bool,
    },
}

/// Declarative description of a command a plugin registers with the
/// proxy's dispatcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCommandSpec {
    pub label: String,
    pub aliases: Vec<String>,
    pub permission: Option<String>,
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

/// Who ran a command. The console sender has no UUID and is granted every node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSender {
    pub uuid: Option<Uuid>,
    pub name: String,
    pub permissions: Vec<String>,
    pub is_console: bool,
}

impl CommandSender {
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
    pub permissions: Vec<PluginPermission>,
}

impl PluginMetadata {
    /// Convenience constructor for guests building their manifest in code.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            author: String::new(),
            description: String::new(),
            min_proxy_version: "0.1.0".to_string(),
            dependencies: Vec::new(),
            permissions: Vec::new(),
        }
    }
}

/// Capability flags a plugin's manifest declares; the host enforces these
/// against the operator's allowlist at load time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginPermission {
    ReadPlayerInfo,
    KickPlayer,
    SendMessage,
    Broadcast,
    ModifyPackets,
    ReadPackets,
    AccessServers,
    RegisterServers,
    AccessRouting,
    ReadConfig,
    ExecuteCommands,
    /// Issue moderation sanctions (warn / mute / ban) against players.
    ManageSanctions,
    /// Open Redis connections and publish/subscribe/get/set via host imports.
    UseRedis,
    /// Make outbound HTTP requests via the host import.
    UseHttp,
}

/// Snake_case wire name for a permission (matches the serde rename).
pub fn permission_name(p: &PluginPermission) -> &'static str {
    match p {
        PluginPermission::ReadPlayerInfo => "read_player_info",
        PluginPermission::KickPlayer => "kick_player",
        PluginPermission::SendMessage => "send_message",
        PluginPermission::Broadcast => "broadcast",
        PluginPermission::ModifyPackets => "modify_packets",
        PluginPermission::ReadPackets => "read_packets",
        PluginPermission::AccessServers => "access_servers",
        PluginPermission::RegisterServers => "register_servers",
        PluginPermission::AccessRouting => "access_routing",
        PluginPermission::ReadConfig => "read_config",
        PluginPermission::ExecuteCommands => "execute_commands",
        PluginPermission::ManageSanctions => "manage_sanctions",
        PluginPermission::UseRedis => "use_redis",
        PluginPermission::UseHttp => "use_http",
    }
}

/// Map a player-supplied permission/config map into a [`HashMap`] (helper
/// re-exported for guests that build config tables).
pub type ConfigMap = HashMap<String, String>;
