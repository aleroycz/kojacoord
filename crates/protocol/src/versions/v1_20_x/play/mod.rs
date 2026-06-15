use bytes::{Buf, Bytes, BytesMut};

use crate::codec::{Decode, DecodeVer, Encode, PacketId};
use crate::error::ProtocolError;
use crate::types::VarInt;

#[derive(Debug, Clone, PartialEq)]
pub enum BossBarAction {
    Add {
        title: String,
        health: f32,
        color: VarInt,
        division: VarInt,
        flags: u8,
    },
    Remove,
    UpdateHealth {
        health: f32,
    },
    UpdateTitle {
        title: String,
    },
    UpdateStyle {
        color: VarInt,
        division: VarInt,
    },
    UpdateFlags {
        flags: u8,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundBossBar {
    pub uuid: uuid::Uuid,
    pub action: BossBarAction,
}

impl PacketId for ClientboundBossBar {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundBossBar")
    }
}

impl Encode for ClientboundBossBar {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.uuid.encode(dst)?;
        match &self.action {
            BossBarAction::Add {
                title,
                health,
                color,
                division,
                flags,
            } => {
                VarInt(0).encode(dst)?;
                title.encode(dst)?;
                health.encode(dst)?;
                color.encode(dst)?;
                division.encode(dst)?;
                flags.encode(dst)?;
            },
            BossBarAction::Remove => VarInt(1).encode(dst)?,
            BossBarAction::UpdateHealth { health } => {
                VarInt(2).encode(dst)?;
                health.encode(dst)?;
            },
            BossBarAction::UpdateTitle { title } => {
                VarInt(3).encode(dst)?;
                title.encode(dst)?;
            },
            BossBarAction::UpdateStyle { color, division } => {
                VarInt(4).encode(dst)?;
                color.encode(dst)?;
                division.encode(dst)?;
            },
            BossBarAction::UpdateFlags { flags } => {
                VarInt(5).encode(dst)?;
                flags.encode(dst)?;
            },
        }
        Ok(())
    }
}

impl Decode for ClientboundBossBar {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let uuid = uuid::Uuid::decode(src)?;
        let action = match VarInt::decode(src)?.0 {
            0 => BossBarAction::Add {
                title: String::decode(src)?,
                health: f32::decode(src)?,
                color: VarInt::decode(src)?,
                division: VarInt::decode(src)?,
                flags: u8::decode(src)?,
            },
            1 => BossBarAction::Remove,
            2 => BossBarAction::UpdateHealth {
                health: f32::decode(src)?,
            },
            3 => BossBarAction::UpdateTitle {
                title: String::decode(src)?,
            },
            4 => BossBarAction::UpdateStyle {
                color: VarInt::decode(src)?,
                division: VarInt::decode(src)?,
            },
            5 => BossBarAction::UpdateFlags {
                flags: u8::decode(src)?,
            },
            _ => return Err(ProtocolError::UnexpectedEof),
        };
        Ok(Self { uuid, action })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundDisconnect {
    pub reason: String,
}

impl PacketId for ClientboundDisconnect {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundDisconnect")
    }
}

impl Encode for ClientboundDisconnect {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.reason.encode(dst)
    }
}

impl Decode for ClientboundDisconnect {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            reason: String::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundKeepAlive {
    pub id: i64,
}

impl PacketId for ClientboundKeepAlive {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundKeepAlive")
    }
}

impl Encode for ClientboundKeepAlive {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.id.encode(dst)
    }
}

impl Decode for ClientboundKeepAlive {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            id: i64::decode(src)?,
        })
    }
}

/// Wire-format variant for the `dimension_type` field of
/// `ClientboundLogin`. Picked by the caller based on negotiated proto:
/// see the field docs on `ClientboundLogin::dimension_type`.
#[derive(Debug, Clone, PartialEq)]
pub enum DimensionTypeRef {
    /// 1.20.2 / 1.20.4 wire format — Identifier (length-prefixed UTF-8).
    Identifier(String),
    /// 1.20.5 / 1.20.6 wire format — VarInt registry index.
    Registry(VarInt),
}

impl Encode for DimensionTypeRef {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        match self {
            DimensionTypeRef::Identifier(s) => s.encode(dst),
            DimensionTypeRef::Registry(v) => v.encode(dst),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundLogin {
    pub entity_id: i32,
    pub is_hardcore: bool,

    pub dimension_names: Vec<String>,
    pub max_players: VarInt,
    pub view_distance: VarInt,
    pub simulation_distance: VarInt,
    pub reduced_debug_info: bool,
    pub enable_respawn_screen: bool,
    /// Added in 1.20.3 (proto 765). Per minecraft.wiki
    /// Java_Edition_protocol/Packets#Login_(Play) — proto 764
    /// (1.20.2) must NOT carry this field on the wire. Use
    /// `None` to omit, `Some(bool)` to emit.
    pub do_limited_crafting: Option<bool>,

    /// Wire type for `dimension_type` changed within the v1_20_x bucket:
    ///   * 1.20.2 / 1.20.4 (proto 764 / 765) → `Identifier` (String,
    ///     e.g. `"minecraft:overworld"`)
    ///   * 1.20.5 / 1.20.6 (proto 766)       → `VarInt` registry index
    ///
    /// The caller picks the variant matching the negotiated proto;
    /// the encoder writes whichever is set.
    pub dimension_type: DimensionTypeRef,
    pub dimension_name: String,
    pub hashed_seed: i64,
    pub game_mode: u8,

    pub previous_game_mode: i8,
    pub is_debug: bool,
    pub is_flat: bool,

    pub death_location: Option<(String, i64)>,
    pub portal_cooldown: VarInt,
    /// Per BungeeCord `Login.java::read`: `secureProfile` was
    /// introduced in proto 766 (1.20.5). For 1.20.0 / 1.20.2 / 1.20.4
    /// (proto 763 / 764 / 765) the field is absent. `None` ⇒ omit.
    pub secure_profile: Option<bool>,
}

impl PacketId for ClientboundLogin {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundLogin")
    }
}

impl Encode for ClientboundLogin {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.entity_id.encode(dst)?;
        self.is_hardcore.encode(dst)?;
        self.dimension_names.encode(dst)?;
        self.max_players.encode(dst)?;
        self.view_distance.encode(dst)?;
        self.simulation_distance.encode(dst)?;
        self.reduced_debug_info.encode(dst)?;
        self.enable_respawn_screen.encode(dst)?;
        if let Some(b) = self.do_limited_crafting {
            b.encode(dst)?;
        }
        self.dimension_type.encode(dst)?;
        self.dimension_name.encode(dst)?;
        self.hashed_seed.encode(dst)?;
        self.game_mode.encode(dst)?;
        self.previous_game_mode.encode(dst)?;
        self.is_debug.encode(dst)?;
        self.is_flat.encode(dst)?;
        match &self.death_location {
            Some((dim, pos)) => {
                true.encode(dst)?;
                dim.encode(dst)?;
                pos.encode(dst)?;
            },
            None => false.encode(dst)?,
        }
        self.portal_cooldown.encode(dst)?;
        if let Some(b) = self.secure_profile {
            b.encode(dst)?;
        }
        Ok(())
    }
}

impl DecodeVer for ClientboundLogin {
    fn decode_ver(ver: u32, src: &mut Bytes) -> Result<Self, ProtocolError> {
        let entity_id = i32::decode(src)?;
        let is_hardcore = bool::decode(src)?;
        let dimension_names = Vec::<String>::decode(src)?;
        let max_players = VarInt::decode(src)?;
        let view_distance = VarInt::decode(src)?;
        let simulation_distance = VarInt::decode(src)?;
        let reduced_debug_info = bool::decode(src)?;
        let enable_respawn_screen = bool::decode(src)?;
        let do_limited_crafting = None;
        let dimension_type = if ver <= 765 {
            DimensionTypeRef::Identifier(String::decode(src)?)
        } else {
            DimensionTypeRef::Registry(VarInt::decode(src)?)
        };
        let dimension_name = String::decode(src)?;
        let hashed_seed = i64::decode(src)?;
        let game_mode = u8::decode(src)?;
        let previous_game_mode = i8::decode(src)?;
        let is_debug = bool::decode(src)?;
        let is_flat = bool::decode(src)?;
        let death_location = if bool::decode(src)? {
            Some((String::decode(src)?, i64::decode(src)?))
        } else {
            None
        };
        let portal_cooldown = VarInt::decode(src)?;
        let secure_profile = None;
        Ok(Self {
            entity_id,
            is_hardcore,
            dimension_names,
            max_players,
            view_distance,
            simulation_distance,
            reduced_debug_info,
            enable_respawn_screen,
            do_limited_crafting,
            dimension_type,
            dimension_name,
            hashed_seed,
            game_mode,
            previous_game_mode,
            is_debug,
            is_flat,
            death_location,
            portal_cooldown,
            secure_profile,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundPluginMessage {
    pub channel: String,
    pub data: Vec<u8>,
}

impl PacketId for ClientboundPluginMessage {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundPluginMessage")
    }
}

impl Encode for ClientboundPluginMessage {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.channel.encode(dst)?;
        dst.extend_from_slice(&self.data);
        Ok(())
    }
}

impl Decode for ClientboundPluginMessage {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let channel = String::decode(src)?;
        let data = src.copy_to_bytes(src.remaining()).to_vec();
        Ok(Self { channel, data })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundPlayerPosition {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub yaw: f32,
    pub pitch: f32,

    pub flags: u8,

    pub teleport_id: VarInt,
}

impl PacketId for ClientboundPlayerPosition {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundPlayerPosition")
    }
}

impl Encode for ClientboundPlayerPosition {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.x.encode(dst)?;
        self.y.encode(dst)?;
        self.z.encode(dst)?;
        self.yaw.encode(dst)?;
        self.pitch.encode(dst)?;
        self.flags.encode(dst)?;
        self.teleport_id.encode(dst)
    }
}

impl Decode for ClientboundPlayerPosition {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            x: f64::decode(src)?,
            y: f64::decode(src)?,
            z: f64::decode(src)?,
            yaw: f32::decode(src)?,
            pitch: f32::decode(src)?,
            flags: u8::decode(src)?,
            teleport_id: VarInt::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundRespawn {
    pub dimension_type: VarInt,
    pub dimension_name: String,
    pub hashed_seed: i64,
    pub game_mode: u8,
    pub previous_game_mode: i8,
    pub is_debug: bool,
    pub is_flat: bool,

    pub data_kept: u8,
    pub death_location: Option<(String, i64)>,
    pub portal_cooldown: VarInt,
}

impl PacketId for ClientboundRespawn {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundRespawn")
    }
}

impl Encode for ClientboundRespawn {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.dimension_type.encode(dst)?;
        self.dimension_name.encode(dst)?;
        self.hashed_seed.encode(dst)?;
        self.game_mode.encode(dst)?;
        self.previous_game_mode.encode(dst)?;
        self.is_debug.encode(dst)?;
        self.is_flat.encode(dst)?;
        self.data_kept.encode(dst)?;
        match &self.death_location {
            Some((dim, pos)) => {
                true.encode(dst)?;
                dim.encode(dst)?;
                pos.encode(dst)?;
            },
            None => false.encode(dst)?,
        }
        self.portal_cooldown.encode(dst)
    }
}

impl Decode for ClientboundRespawn {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let dimension_type = VarInt::decode(src)?;
        let dimension_name = String::decode(src)?;
        let hashed_seed = i64::decode(src)?;
        let game_mode = u8::decode(src)?;
        let previous_game_mode = i8::decode(src)?;
        let is_debug = bool::decode(src)?;
        let is_flat = bool::decode(src)?;
        let data_kept = u8::decode(src)?;
        let death_location = if bool::decode(src)? {
            Some((String::decode(src)?, i64::decode(src)?))
        } else {
            None
        };
        let portal_cooldown = VarInt::decode(src)?;
        Ok(Self {
            dimension_type,
            dimension_name,
            hashed_seed,
            game_mode,
            previous_game_mode,
            is_debug,
            is_flat,
            data_kept,
            death_location,
            portal_cooldown,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundPlayerAbilities {
    pub flags: u8,
    pub flying_speed: f32,

    pub walking_speed: f32,
}

impl PacketId for ClientboundPlayerAbilities {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundPlayerAbilities")
    }
}

impl Encode for ClientboundPlayerAbilities {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.flags.encode(dst)?;
        self.flying_speed.encode(dst)?;
        self.walking_speed.encode(dst)
    }
}

impl Decode for ClientboundPlayerAbilities {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            flags: u8::decode(src)?,
            flying_speed: f32::decode(src)?,
            walking_speed: f32::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundSetCarriedItem {
    pub slot: i8,
}

impl PacketId for ClientboundSetCarriedItem {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundSetCarriedItem")
    }
}

impl Encode for ClientboundSetCarriedItem {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.slot.encode(dst)
    }
}

impl Decode for ClientboundSetCarriedItem {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            slot: i8::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundSystemChat {
    pub content: String,

    pub overlay: bool,
}

impl PacketId for ClientboundSystemChat {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundSystemChat")
    }
}

impl Encode for ClientboundSystemChat {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.content.encode(dst)?;
        self.overlay.encode(dst)
    }
}

impl Decode for ClientboundSystemChat {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            content: String::decode(src)?,
            overlay: bool::decode(src)?,
        })
    }
}
