use bytes::{Buf, Bytes, BytesMut};

use crate::codec::{Decode, Encode, PacketId};
use crate::error::ProtocolError;
use crate::types::VarInt;

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundAcceptTeleportation {
    pub teleport_id: VarInt,
}

impl PacketId for ServerboundAcceptTeleportation {
    fn packet_id(_ver: u32) -> u8 {
        0x05
    }
}

impl Encode for ServerboundAcceptTeleportation {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.teleport_id.encode(dst)
    }
}

impl Decode for ServerboundAcceptTeleportation {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            teleport_id: VarInt::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundClientInformation {
    pub locale: String,

    pub view_distance: i8,

    pub chat_mode: VarInt,

    pub chat_colors: bool,

    pub displayed_skin_parts: u8,

    pub main_hand: VarInt,

    pub enable_text_filtering: bool,

    pub allow_server_listings: bool,
}

impl PacketId for ServerboundClientInformation {
    fn packet_id(_ver: u32) -> u8 {
        0x09
    }
}

impl Encode for ServerboundClientInformation {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.locale.encode(dst)?;
        self.view_distance.encode(dst)?;
        self.chat_mode.encode(dst)?;
        self.chat_colors.encode(dst)?;
        self.displayed_skin_parts.encode(dst)?;
        self.main_hand.encode(dst)?;
        self.enable_text_filtering.encode(dst)?;
        self.allow_server_listings.encode(dst)
    }
}

impl Decode for ServerboundClientInformation {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            locale: String::decode(src)?,
            view_distance: i8::decode(src)?,
            chat_mode: VarInt::decode(src)?,
            chat_colors: bool::decode(src)?,
            displayed_skin_parts: u8::decode(src)?,
            main_hand: VarInt::decode(src)?,
            enable_text_filtering: bool::decode(src)?,
            allow_server_listings: bool::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InteractAction {
    Interact {
        hand: VarInt,
    },

    Attack,

    InteractAt {
        target_x: f32,
        target_y: f32,
        target_z: f32,
        hand: VarInt,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundInteract {
    pub entity_id: VarInt,

    pub action: InteractAction,

    pub sneaking: bool,
}

impl PacketId for ServerboundInteract {
    fn packet_id(_ver: u32) -> u8 {
        0x13
    }
}

impl Encode for ServerboundInteract {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.entity_id.encode(dst)?;
        match &self.action {
            InteractAction::Interact { hand } => {
                VarInt(0).encode(dst)?;
                hand.encode(dst)?;
            },
            InteractAction::Attack => {
                VarInt(1).encode(dst)?;
            },
            InteractAction::InteractAt {
                target_x,
                target_y,
                target_z,
                hand,
            } => {
                VarInt(2).encode(dst)?;
                target_x.encode(dst)?;
                target_y.encode(dst)?;
                target_z.encode(dst)?;
                hand.encode(dst)?;
            },
        }
        self.sneaking.encode(dst)
    }
}

impl Decode for ServerboundInteract {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let entity_id = VarInt::decode(src)?;
        let action = match VarInt::decode(src)?.0 {
            0 => InteractAction::Interact {
                hand: VarInt::decode(src)?,
            },
            1 => InteractAction::Attack,
            2 => InteractAction::InteractAt {
                target_x: f32::decode(src)?,
                target_y: f32::decode(src)?,
                target_z: f32::decode(src)?,
                hand: VarInt::decode(src)?,
            },
            _ => return Err(ProtocolError::UnexpectedEof),
        };
        let sneaking = bool::decode(src)?;
        Ok(Self {
            entity_id,
            action,
            sneaking,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundKeepAlive {
    pub id: i64,
}

impl PacketId for ServerboundKeepAlive {
    fn packet_id(_ver: u32) -> u8 {
        0x18
    }
}

impl Encode for ServerboundKeepAlive {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.id.encode(dst)
    }
}

impl Decode for ServerboundKeepAlive {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            id: i64::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundMovePlayerStatusOnly {
    pub on_ground: bool,
}

impl PacketId for ServerboundMovePlayerStatusOnly {
    fn packet_id(_ver: u32) -> u8 {
        0x14
    }
}

impl Encode for ServerboundMovePlayerStatusOnly {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.on_ground.encode(dst)
    }
}

impl Decode for ServerboundMovePlayerStatusOnly {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            on_ground: bool::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundMovePlayerPos {
    pub x: f64,
    pub feet_y: f64,
    pub z: f64,
    pub on_ground: bool,
}

impl PacketId for ServerboundMovePlayerPos {
    fn packet_id(_ver: u32) -> u8 {
        0x15
    }
}

impl Encode for ServerboundMovePlayerPos {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.x.encode(dst)?;
        self.feet_y.encode(dst)?;
        self.z.encode(dst)?;
        self.on_ground.encode(dst)
    }
}

impl Decode for ServerboundMovePlayerPos {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            x: f64::decode(src)?,
            feet_y: f64::decode(src)?,
            z: f64::decode(src)?,
            on_ground: bool::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundMovePlayerRot {
    pub yaw: f32,
    pub pitch: f32,
    pub on_ground: bool,
}

impl PacketId for ServerboundMovePlayerRot {
    fn packet_id(_ver: u32) -> u8 {
        0x16
    }
}

impl Encode for ServerboundMovePlayerRot {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.yaw.encode(dst)?;
        self.pitch.encode(dst)?;
        self.on_ground.encode(dst)
    }
}

impl Decode for ServerboundMovePlayerRot {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            yaw: f32::decode(src)?,
            pitch: f32::decode(src)?,
            on_ground: bool::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundMovePlayerPosRot {
    pub x: f64,
    pub feet_y: f64,
    pub z: f64,
    pub yaw: f32,
    pub pitch: f32,
    pub on_ground: bool,
}

impl PacketId for ServerboundMovePlayerPosRot {
    fn packet_id(_ver: u32) -> u8 {
        0x17
    }
}

impl Encode for ServerboundMovePlayerPosRot {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.x.encode(dst)?;
        self.feet_y.encode(dst)?;
        self.z.encode(dst)?;
        self.yaw.encode(dst)?;
        self.pitch.encode(dst)?;
        self.on_ground.encode(dst)
    }
}

impl Decode for ServerboundMovePlayerPosRot {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            x: f64::decode(src)?,
            feet_y: f64::decode(src)?,
            z: f64::decode(src)?,
            yaw: f32::decode(src)?,
            pitch: f32::decode(src)?,
            on_ground: bool::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundPluginMessage {
    pub channel: String,
    pub data: Vec<u8>,
}

impl PacketId for ServerboundPluginMessage {
    fn packet_id(_ver: u32) -> u8 {
        0x0F
    }
}

impl Encode for ServerboundPluginMessage {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.channel.encode(dst)?;
        dst.extend_from_slice(&self.data);
        Ok(())
    }
}

impl Decode for ServerboundPluginMessage {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let channel = String::decode(src)?;
        let data = src.copy_to_bytes(src.remaining()).to_vec();
        Ok(Self { channel, data })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundPlayerAbilities {
    pub flags: u8,
}

impl PacketId for ServerboundPlayerAbilities {
    fn packet_id(_ver: u32) -> u8 {
        0x22
    }
}

impl Encode for ServerboundPlayerAbilities {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.flags.encode(dst)
    }
}

impl Decode for ServerboundPlayerAbilities {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            flags: u8::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundPlayerAction {
    pub status: VarInt,

    pub location: i64,

    pub face: i8,

    pub sequence: VarInt,
}

impl PacketId for ServerboundPlayerAction {
    fn packet_id(_ver: u32) -> u8 {
        0x24
    }
}

impl Encode for ServerboundPlayerAction {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.status.encode(dst)?;
        self.location.encode(dst)?;
        self.face.encode(dst)?;
        self.sequence.encode(dst)
    }
}

impl Decode for ServerboundPlayerAction {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            status: VarInt::decode(src)?,
            location: i64::decode(src)?,
            face: i8::decode(src)?,
            sequence: VarInt::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundSetCarriedItem {
    pub slot: i16,
}

impl PacketId for ServerboundSetCarriedItem {
    fn packet_id(_ver: u32) -> u8 {
        0x2C
    }
}

impl Encode for ServerboundSetCarriedItem {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.slot.encode(dst)
    }
}

impl Decode for ServerboundSetCarriedItem {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            slot: i16::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundSwingArm {
    pub hand: VarInt,
}

impl PacketId for ServerboundSwingArm {
    fn packet_id(_ver: u32) -> u8 {
        0x33
    }
}

impl Encode for ServerboundSwingArm {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.hand.encode(dst)
    }
}

impl Decode for ServerboundSwingArm {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            hand: VarInt::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundUseItemOn {
    pub hand: VarInt,

    pub location: i64,

    pub face: VarInt,

    pub cursor_x: f32,

    pub cursor_y: f32,

    pub cursor_z: f32,

    pub inside_block: bool,

    pub sequence: VarInt,
}

impl PacketId for ServerboundUseItemOn {
    fn packet_id(_ver: u32) -> u8 {
        0x36
    }
}

impl Encode for ServerboundUseItemOn {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.hand.encode(dst)?;
        self.location.encode(dst)?;
        self.face.encode(dst)?;
        self.cursor_x.encode(dst)?;
        self.cursor_y.encode(dst)?;
        self.cursor_z.encode(dst)?;
        self.inside_block.encode(dst)?;
        self.sequence.encode(dst)
    }
}

impl Decode for ServerboundUseItemOn {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            hand: VarInt::decode(src)?,
            location: i64::decode(src)?,
            face: VarInt::decode(src)?,
            cursor_x: f32::decode(src)?,
            cursor_y: f32::decode(src)?,
            cursor_z: f32::decode(src)?,
            inside_block: bool::decode(src)?,
            sequence: VarInt::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundUseItem {
    pub hand: VarInt,

    pub sequence: VarInt,
}

impl PacketId for ServerboundUseItem {
    fn packet_id(_ver: u32) -> u8 {
        0x37
    }
}

impl Encode for ServerboundUseItem {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.hand.encode(dst)?;
        self.sequence.encode(dst)
    }
}

impl Decode for ServerboundUseItem {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            hand: VarInt::decode(src)?,
            sequence: VarInt::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundBundleDelimiter;

impl PacketId for ClientboundBundleDelimiter {
    fn packet_id(_ver: u32) -> u8 {
        0x00
    }
}

impl Encode for ClientboundBundleDelimiter {
    fn encode(&self, _dst: &mut BytesMut) -> Result<(), ProtocolError> {
        Ok(())
    }
}

impl Decode for ClientboundBundleDelimiter {
    fn decode(_src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self)
    }
}

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
    fn packet_id(_ver: u32) -> u8 {
        0x0A
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
    fn packet_id(_ver: u32) -> u8 {
        0x1A
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
pub struct ClientboundEntityEvent {
    pub entity_id: i32,

    pub event_id: i8,
}

impl PacketId for ClientboundEntityEvent {
    fn packet_id(_ver: u32) -> u8 {
        0x1C
    }
}

impl Encode for ClientboundEntityEvent {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.entity_id.encode(dst)?;
        self.event_id.encode(dst)
    }
}

impl Decode for ClientboundEntityEvent {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            entity_id: i32::decode(src)?,
            event_id: i8::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundGameEvent {
    pub event: u8,

    pub value: f32,
}

impl PacketId for ClientboundGameEvent {
    fn packet_id(_ver: u32) -> u8 {
        0x1E
    }
}

impl Encode for ClientboundGameEvent {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.event.encode(dst)?;
        self.value.encode(dst)
    }
}

impl Decode for ClientboundGameEvent {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            event: u8::decode(src)?,
            value: f32::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundKeepAlive {
    pub id: i64,
}

impl PacketId for ClientboundKeepAlive {
    fn packet_id(_ver: u32) -> u8 {
        0x24
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
    pub do_limited_crafting: bool,

    pub dimension_type: VarInt,
    pub dimension_name: String,
    pub hashed_seed: i64,
    pub game_mode: u8,

    pub previous_game_mode: i8,
    pub is_debug: bool,
    pub is_flat: bool,

    pub death_location: Option<(String, i64)>,
    pub portal_cooldown: VarInt,
}

impl PacketId for ClientboundLogin {
    fn packet_id(_ver: u32) -> u8 {
        0x29
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
        self.do_limited_crafting.encode(dst)?;
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
        self.portal_cooldown.encode(dst)
    }
}

impl Decode for ClientboundLogin {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let entity_id = i32::decode(src)?;
        let is_hardcore = bool::decode(src)?;
        let dimension_names = Vec::<String>::decode(src)?;
        let max_players = VarInt::decode(src)?;
        let view_distance = VarInt::decode(src)?;
        let simulation_distance = VarInt::decode(src)?;
        let reduced_debug_info = bool::decode(src)?;
        let enable_respawn_screen = bool::decode(src)?;
        let do_limited_crafting = bool::decode(src)?;
        let dimension_type = VarInt::decode(src)?;
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
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundPluginMessage {
    pub channel: String,
    pub data: Vec<u8>,
}

impl PacketId for ClientboundPluginMessage {
    fn packet_id(_ver: u32) -> u8 {
        0x17
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
    fn packet_id(_ver: u32) -> u8 {
        0x3E
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
    fn packet_id(_ver: u32) -> u8 {
        0x43
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
    fn packet_id(_ver: u32) -> u8 {
        0x40
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
    fn packet_id(_ver: u32) -> u8 {
        0x53
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
pub struct ClientboundSetDefaultSpawnPosition {
    pub location: i64,
    pub angle: f32,
}

impl PacketId for ClientboundSetDefaultSpawnPosition {
    fn packet_id(_ver: u32) -> u8 {
        0x54
    }
}

impl Encode for ClientboundSetDefaultSpawnPosition {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.location.encode(dst)?;
        self.angle.encode(dst)
    }
}

impl Decode for ClientboundSetDefaultSpawnPosition {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            location: i64::decode(src)?,
            angle: f32::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundSetTime {
    pub world_age: i64,

    pub time_of_day: i64,
}

impl PacketId for ClientboundSetTime {
    fn packet_id(_ver: u32) -> u8 {
        0x62
    }
}

impl Encode for ClientboundSetTime {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.world_age.encode(dst)?;
        self.time_of_day.encode(dst)
    }
}

impl Decode for ClientboundSetTime {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            world_age: i64::decode(src)?,
            time_of_day: i64::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundSystemChat {
    pub content: String,

    pub overlay: bool,
}

impl PacketId for ClientboundSystemChat {
    fn packet_id(_ver: u32) -> u8 {
        0x6C
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_teleportation_roundtrip() {
        let p = ServerboundAcceptTeleportation {
            teleport_id: VarInt(7),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ServerboundAcceptTeleportation::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn client_information_roundtrip() {
        let p = ServerboundClientInformation {
            locale: "en_US".to_string(),
            view_distance: 12,
            chat_mode: VarInt(0),
            chat_colors: true,
            displayed_skin_parts: 0x7F,
            main_hand: VarInt(1),
            enable_text_filtering: false,
            allow_server_listings: true,
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ServerboundClientInformation::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn keep_alive_roundtrip() {
        let p = ClientboundKeepAlive { id: 987654321 };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(ClientboundKeepAlive::decode(&mut buf.freeze()).unwrap(), p);

        let p2 = ServerboundKeepAlive { id: 987654321 };
        let mut buf2 = BytesMut::new();
        p2.encode(&mut buf2).unwrap();
        assert_eq!(
            ServerboundKeepAlive::decode(&mut buf2.freeze()).unwrap(),
            p2
        );
    }

    #[test]
    fn move_pos_roundtrip() {
        let p = ServerboundMovePlayerPos {
            x: 3.5,
            feet_y: 64.0,
            z: 2.71,
            on_ground: true,
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ServerboundMovePlayerPos::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn move_pos_rot_roundtrip() {
        let p = ServerboundMovePlayerPosRot {
            x: 1.0,
            feet_y: 65.0,
            z: -1.0,
            yaw: 45.0,
            pitch: -10.0,
            on_ground: false,
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ServerboundMovePlayerPosRot::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn move_rot_roundtrip() {
        let p = ServerboundMovePlayerRot {
            yaw: 90.0,
            pitch: 0.0,
            on_ground: true,
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ServerboundMovePlayerRot::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn move_status_only_roundtrip() {
        let p = ServerboundMovePlayerStatusOnly { on_ground: false };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ServerboundMovePlayerStatusOnly::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn interact_interact_at_roundtrip() {
        let p = ServerboundInteract {
            entity_id: VarInt(12),
            action: InteractAction::InteractAt {
                target_x: 0.5,
                target_y: 0.5,
                target_z: 0.5,
                hand: VarInt(1),
            },
            sneaking: true,
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(ServerboundInteract::decode(&mut buf.freeze()).unwrap(), p);
    }

    #[test]
    fn player_position_roundtrip() {
        let p = ClientboundPlayerPosition {
            x: 0.0,
            y: 64.0,
            z: 0.0,
            yaw: 90.0,
            pitch: 5.0,
            flags: 0x1F,
            teleport_id: VarInt(2),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ClientboundPlayerPosition::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn plugin_message_roundtrip() {
        let p = ClientboundPluginMessage {
            channel: "minecraft:brand".to_string(),
            data: b"purpur".to_vec(),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ClientboundPluginMessage::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn disconnect_roundtrip() {
        let p = ClientboundDisconnect {
            reason: r#"{"text":"server closing"}"#.to_string(),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(ClientboundDisconnect::decode(&mut buf.freeze()).unwrap(), p);
    }

    #[test]
    fn game_event_roundtrip() {
        let p = ClientboundGameEvent {
            event: 3,
            value: 1.0,
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(ClientboundGameEvent::decode(&mut buf.freeze()).unwrap(), p);
    }

    #[test]
    fn system_chat_roundtrip() {
        let p = ClientboundSystemChat {
            content: r#"{"text":"Hello!"}"#.to_string(),
            overlay: false,
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(ClientboundSystemChat::decode(&mut buf.freeze()).unwrap(), p);
    }

    #[test]
    fn set_time_roundtrip() {
        let p = ClientboundSetTime {
            world_age: 24000,
            time_of_day: 6000,
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(ClientboundSetTime::decode(&mut buf.freeze()).unwrap(), p);
    }

    #[test]
    fn respawn_roundtrip() {
        let p = ClientboundRespawn {
            dimension_type: VarInt(0),
            dimension_name: "minecraft:overworld".to_string(),
            hashed_seed: 0,
            game_mode: 0,
            previous_game_mode: -1,
            is_debug: false,
            is_flat: false,
            data_kept: 0x01,
            death_location: None,
            portal_cooldown: VarInt(0),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(ClientboundRespawn::decode(&mut buf.freeze()).unwrap(), p);
    }

    #[test]
    fn boss_bar_add_roundtrip() {
        let p = ClientboundBossBar {
            uuid: uuid::Uuid::new_v4(),
            action: BossBarAction::Add {
                title: r#"{"text":"Boss"}"#.to_string(),
                health: 0.75,
                color: VarInt(1),
                division: VarInt(0),
                flags: 0,
            },
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(ClientboundBossBar::decode(&mut buf.freeze()).unwrap(), p);
    }

    #[test]
    fn packet_ids() {
        assert_eq!(ServerboundAcceptTeleportation::packet_id(765), 0x05);
        assert_eq!(ServerboundClientInformation::packet_id(765), 0x09);
        assert_eq!(ServerboundInteract::packet_id(765), 0x13);
        assert_eq!(ServerboundKeepAlive::packet_id(765), 0x18);
        assert_eq!(ServerboundMovePlayerStatusOnly::packet_id(765), 0x14);
        assert_eq!(ServerboundMovePlayerPos::packet_id(765), 0x15);
        assert_eq!(ServerboundMovePlayerRot::packet_id(765), 0x16);
        assert_eq!(ServerboundMovePlayerPosRot::packet_id(765), 0x17);
        assert_eq!(ServerboundPluginMessage::packet_id(765), 0x0F);
        assert_eq!(ServerboundPlayerAbilities::packet_id(765), 0x22);
        assert_eq!(ServerboundPlayerAction::packet_id(765), 0x24);
        assert_eq!(ServerboundSetCarriedItem::packet_id(765), 0x2C);
        assert_eq!(ServerboundSwingArm::packet_id(765), 0x33);
        assert_eq!(ServerboundUseItemOn::packet_id(765), 0x36);
        assert_eq!(ServerboundUseItem::packet_id(765), 0x37);
        assert_eq!(ClientboundBundleDelimiter::packet_id(765), 0x00);
        assert_eq!(ClientboundBossBar::packet_id(765), 0x0A);
        assert_eq!(ClientboundDisconnect::packet_id(765), 0x1A);
        assert_eq!(ClientboundEntityEvent::packet_id(765), 0x1C);
        assert_eq!(ClientboundGameEvent::packet_id(765), 0x1E);
        assert_eq!(ClientboundKeepAlive::packet_id(765), 0x24);
        assert_eq!(ClientboundLogin::packet_id(765), 0x29);
        assert_eq!(ClientboundPluginMessage::packet_id(765), 0x17);
        assert_eq!(ClientboundPlayerPosition::packet_id(765), 0x3E);
        assert_eq!(ClientboundRespawn::packet_id(765), 0x43);
        assert_eq!(ClientboundPlayerAbilities::packet_id(765), 0x40);
        assert_eq!(ClientboundSetCarriedItem::packet_id(765), 0x53);
        assert_eq!(ClientboundSetDefaultSpawnPosition::packet_id(765), 0x54);
        assert_eq!(ClientboundSetTime::packet_id(765), 0x62);
        assert_eq!(ClientboundSystemChat::packet_id(765), 0x6C);
    }
}
