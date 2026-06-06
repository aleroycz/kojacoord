// Author : Starfloof.
use bytes::Bytes;
use kojacoord_protocol::{
    codec::Decode,
    registry::{build_default_registry, Direction, ProtocolState},
    types::VarInt,
    ProtocolVersion, VersionRegistry,
};

lazy_static::lazy_static! {
    static ref REGISTRY: kojacoord_protocol::registry::PacketRegistry = build_default_registry();
}

#[derive(Debug, Clone)]
pub struct MovementData {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub on_ground: bool,
    pub has_pos: bool,
}

#[derive(Debug, Clone)]
pub struct InteractData {
    pub entity_id: i32,
    pub is_attack: bool,
}

/// Data from a ServerboundPlayerAction packet (dig / block interaction).
#[derive(Debug, Clone)]
pub struct DigData {
    /// 0 = START_DIGGING, 1 = CANCEL_DIGGING, 2 = FINISH_DIGGING.
    pub status: u8,
    pub x: i32,
    pub y: i32,
    pub z: i32,
    /// Block face the player is mining (0=bottom … 5=east).
    pub face: u8,
}

#[derive(Debug, Clone)]
pub enum AnticheatPacket {
    Movement(MovementData),
    Interact(InteractData),
    /// Player started / cancelled / finished digging a block.
    Dig(DigData),
    Chat {
        message: String,
    },
    Unknown,
}

pub fn parse_serverbound(payload: &Bytes, protocol_version: u32) -> AnticheatPacket {
    if payload.is_empty() {
        return AnticheatPacket::Unknown;
    }

    let mut cursor = payload.clone();
    let packet_id = match VarInt::decode(&mut cursor) {
        Ok(id) => id.0 as u8,
        Err(_) => return AnticheatPacket::Unknown,
    };

    let ver = VersionRegistry::nearest(protocol_version);
    let reg = &*REGISTRY;

    macro_rules! id_of {
        ($name:expr) => {
            reg.get_id_for_version(
                protocol_version,
                ProtocolState::Play,
                Direction::Serverbound,
                $name,
            )
        };
    }

    if Some(packet_id) == id_of!("ServerboundMovePlayerPosRot") {
        return parse_move_pos_rot(&mut cursor);
    }
    if Some(packet_id) == id_of!("ServerboundMovePlayerPos") {
        return parse_move_pos(&mut cursor);
    }

    let move_pos_rot_id = match ver {
        ProtocolVersion::V1_7_10 | ProtocolVersion::V1_8 => 0x06,
        ProtocolVersion::V1_12_2 => 0x0E,
        ProtocolVersion::V1_16_5 => 0x12,
        ProtocolVersion::V1_19_4 | ProtocolVersion::V1_20_4 | ProtocolVersion::Unknown(_) => 0x14,
        ProtocolVersion::V1_21 => 0x15,
        _ => 0xFF,
    };
    let move_pos_id = match ver {
        ProtocolVersion::V1_7_10 | ProtocolVersion::V1_8 => 0x04,
        ProtocolVersion::V1_12_2 => 0x0C,
        ProtocolVersion::V1_16_5 => 0x10,
        ProtocolVersion::V1_19_4 | ProtocolVersion::V1_20_4 | ProtocolVersion::Unknown(_) => 0x12,
        ProtocolVersion::V1_21 => 0x13,
        _ => 0xFF,
    };

    if packet_id == move_pos_rot_id {
        return parse_move_pos_rot(&mut cursor);
    }
    if packet_id == move_pos_id {
        return parse_move_pos(&mut cursor);
    }

    let interact_id = match ver {
        ProtocolVersion::V1_7_10 | ProtocolVersion::V1_8 => 0x02,
        ProtocolVersion::V1_12_2 => 0x0A,
        ProtocolVersion::V1_16_5 => 0x0E,
        ProtocolVersion::V1_19_4 => 0x10,
        ProtocolVersion::V1_20_4 | ProtocolVersion::Unknown(_) => 0x13,
        ProtocolVersion::V1_21 => 0x14,
        _ => 0xFF,
    };

    if packet_id == interact_id {
        return parse_interact(&mut cursor);
    }

    // ─── ServerboundPlayerAction (digging) ────────────────────────────────
    let dig_id = match ver {
        ProtocolVersion::V1_7_10 | ProtocolVersion::V1_8 => 0x07,
        ProtocolVersion::V1_12_2 => 0x14,
        ProtocolVersion::V1_16_5 => 0x1A,
        ProtocolVersion::V1_19_4 => 0x1D,
        ProtocolVersion::V1_20_4 | ProtocolVersion::Unknown(_) | ProtocolVersion::V1_21 => 0x1C,
        _ => 0xFF,
    };

    if packet_id == dig_id {
        return parse_dig(&mut cursor, ver);
    }

    let chat_ids: &[u8] = match ver {
        ProtocolVersion::V1_7_10 | ProtocolVersion::V1_8 => &[0x01],
        ProtocolVersion::V1_12_2 => &[0x02],
        ProtocolVersion::V1_16_5 => &[0x03],
        ProtocolVersion::V1_19_4 | ProtocolVersion::V1_20_4 | ProtocolVersion::Unknown(_) => {
            &[0x04, 0x05]
        },
        ProtocolVersion::V1_21 => &[0x05, 0x06],
        _ => &[],
    };

    if chat_ids.contains(&packet_id) {
        if let Ok(msg) = String::decode(&mut cursor) {
            return AnticheatPacket::Chat { message: msg };
        }
    }

    AnticheatPacket::Unknown
}

fn parse_move_pos_rot(cursor: &mut Bytes) -> AnticheatPacket {
    let x = f64::decode(cursor).unwrap_or(0.0);
    let y = f64::decode(cursor).unwrap_or(0.0);
    let z = f64::decode(cursor).unwrap_or(0.0);
    let _yaw = f32::decode(cursor).unwrap_or(0.0);
    let _pitch = f32::decode(cursor).unwrap_or(0.0);
    let on_ground = bool::decode(cursor).unwrap_or(false);
    AnticheatPacket::Movement(MovementData {
        x,
        y,
        z,
        on_ground,
        has_pos: true,
    })
}

fn parse_move_pos(cursor: &mut Bytes) -> AnticheatPacket {
    let x = f64::decode(cursor).unwrap_or(0.0);
    let y = f64::decode(cursor).unwrap_or(0.0);
    let z = f64::decode(cursor).unwrap_or(0.0);
    let on_ground = bool::decode(cursor).unwrap_or(false);
    AnticheatPacket::Movement(MovementData {
        x,
        y,
        z,
        on_ground,
        has_pos: true,
    })
}

fn parse_interact(cursor: &mut Bytes) -> AnticheatPacket {
    let entity_id = VarInt::decode(cursor).map(|v| v.0).unwrap_or(0);
    let action = VarInt::decode(cursor).map(|v| v.0).unwrap_or(0);
    let is_attack = action == 1;
    AnticheatPacket::Interact(InteractData {
        entity_id,
        is_attack,
    })
}

/// Parse ServerboundPlayerAction across all supported protocol versions.
///
/// Format:
/// - 1.7/1.8: status(u8) + x(i32) + y(u8) + z(i32) + face(u8)
/// - 1.9+:    status(VarInt) + packed_pos(i64) + face(VarInt) [+ seq(VarInt) 1.19+]
fn parse_dig(cursor: &mut Bytes, ver: ProtocolVersion) -> AnticheatPacket {
    let status = match ver {
        ProtocolVersion::V1_7_10 | ProtocolVersion::V1_8 => u8::decode(cursor).unwrap_or(0xFF),
        _ => VarInt::decode(cursor).map(|v| v.0 as u8).unwrap_or(0xFF),
    };

    let (bx, by, bz) = if matches!(ver, ProtocolVersion::V1_7_10 | ProtocolVersion::V1_8) {
        // 1.7/1.8 separate fields: x(i32) + y(u8) + z(i32)
        let bx = i32::decode(cursor).unwrap_or(0);
        let by = u8::decode(cursor).unwrap_or(0) as i32;
        let bz = i32::decode(cursor).unwrap_or(0);
        (bx, by, bz)
    } else {
        // 1.9+: 64-bit packed block position  X[26] Z[26] Y[12]
        let packed = i64::decode(cursor).unwrap_or(0);
        let bx = (packed >> 38) as i32;
        let by = ((packed << 52) >> 52) as i32;
        let bz = ((packed << 26) >> 38) as i32;
        (bx, by, bz)
    };

    let face = match ver {
        ProtocolVersion::V1_7_10 | ProtocolVersion::V1_8 => u8::decode(cursor).unwrap_or(0),
        _ => VarInt::decode(cursor).map(|v| v.0 as u8).unwrap_or(0),
    };

    AnticheatPacket::Dig(DigData {
        status,
        x: bx,
        y: by,
        z: bz,
        face,
    })
}
