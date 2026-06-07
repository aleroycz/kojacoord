use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub struct PluginContext {
    pub plugin_id: String,
    pub version: String,
    pub config: HashMap<String, String>,
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
}

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

    fn register_packet_hooks(&mut self) -> Vec<PacketEvent> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginResponse {
    None,
    Message(String),
    KickPlayer { uuid: Uuid, reason: String },
    Broadcast(String),
    Custom(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub min_proxy_version: String,
    pub dependencies: Vec<String>,
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
}

impl PacketEvent {
    pub fn hook(filter: PacketFilter, hook: PacketHookFn) -> Self {
        Self { filter, hook }
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
        }
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
}
