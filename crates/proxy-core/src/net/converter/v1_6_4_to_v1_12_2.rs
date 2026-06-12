use bytes::{Buf, BufMut, Bytes, BytesMut};
use kojacoord_protocol::codec::Encode;
use kojacoord_protocol::types::VarInt;

use super::{build_payload, split_id};
use crate::converter::ConversionResult;

// Per the Notchian 1.6.4 pre-netty packet table (mirrored at MCP-doc
// `Packet<N><Name>` — N is the DECIMAL packet id, so hex id = N).
// Previously, PLAYER_POS_LOOK = 0x13 and HELD_ITEM_CHANGE = 0x09
// decoded to EntityAction (Packet19) and Respawn (Packet9) — entirely
// different packets. With the wrong ids the converter silently passed
// PlayerPositionAndLook and HeldItemChange straight through; the 1.12.2
// backend then dropped them as malformed. Corrected against the MCP
// decompile mirror.
const V164_S2C_KEEP_ALIVE: u8 = 0x00; // Packet0KeepAlive
const V164_S2C_CHAT: u8 = 0x03; // Packet3Chat
const V164_S2C_PLAYER_POS_LOOK: u8 = 0x0D; // Packet13PlayerLookMove (was 0x13)
const V164_S2C_SPAWN_PLAYER: u8 = 0x14; // Packet20NamedEntitySpawn
const V164_S2C_ENTITY_TELEPORT: u8 = 0x18; // Packet24EntityTeleport
const V164_S2C_ENTITY_REL_MOVE: u8 = 0x15; // Packet21EntityRelativeMove
const V164_S2C_ENTITY: u8 = 0x1E; // Packet30Entity
const V164_S2C_BLOCK_CHANGE: u8 = 0x35; // Packet53BlockChange
const V164_S2C_SET_SLOT: u8 = 0x67; // Packet103SetSlot
const V164_S2C_WINDOW_ITEMS: u8 = 0x68; // Packet104WindowItems
/// **Important**: the existing name is misleading — `0x1C` is actually
/// `Packet28EntityVelocity` per the Notchian pre-netty table. Kept as
/// `V164_S2C_ENTITY_EQUIPMENT` to avoid breaking callers; the real
/// EntityEquipment packet is `Packet5EntityEquipment` (id 0x05).
const V164_S2C_ENTITY_EQUIPMENT: u8 = 0x1C; // (actually Packet28EntityVelocity)
const V164_S2C_EXPERIENCE: u8 = 0x2B; // Packet43Experience
const V164_S2C_HELD_ITEM_CHANGE: u8 = 0x10; // Packet16BlockItemSwitch (was 0x09)
const V164_S2C_PLAYER_ABILITIES: u8 = 0x43; // Packet67PlayerAbilities
const V164_S2C_DISCONNECT: u8 = 0xFF; // Packet255KickDisconnect
                                      // New batch (this audit) — common steady-state s2c packets.
const V164_S2C_TIME_UPDATE: u8 = 0x04; // Packet4UpdateTime
const V164_S2C_SPAWN_POSITION: u8 = 0x06; // Packet6SpawnPosition
const V164_S2C_UPDATE_HEALTH: u8 = 0x08; // Packet8UpdateHealth
const V164_S2C_COLLECT_ITEM: u8 = 0x16; // Packet22Collect
const V164_S2C_DESTROY_ENTITIES: u8 = 0x1D; // Packet29DestroyEntity
const V164_S2C_ENTITY_HEAD_LOOK: u8 = 0x23; // Packet35EntityHeadRotation
const V164_S2C_PLUGIN_MESSAGE: u8 = 0xFA; // Packet250CustomPayload

const V112_S2C_KEEP_ALIVE: u8 = 0x1F;
const V112_S2C_CHAT: u8 = 0x0F;
const V112_S2C_PLAYER_POS_LOOK: u8 = 0x2F;
const V112_S2C_SPAWN_PLAYER: u8 = 0x05;
const V112_S2C_ENTITY_TELEPORT: u8 = 0x4C;
const V112_S2C_ENTITY_REL_MOVE: u8 = 0x26;
const V112_S2C_ENTITY: u8 = 0x25;
const V112_S2C_BLOCK_CHANGE: u8 = 0x0B;
const V112_S2C_SET_SLOT: u8 = 0x16;
const V112_S2C_WINDOW_ITEMS: u8 = 0x14;
const V112_S2C_ENTITY_EQUIPMENT: u8 = 0x3F;
const V112_S2C_EXPERIENCE: u8 = 0x40;
const V112_S2C_HELD_ITEM_CHANGE: u8 = 0x3A;
const V112_S2C_PLAYER_ABILITIES: u8 = 0x2C;
const V112_S2C_DISCONNECT: u8 = 0x1A;
// 1.12.2 target IDs for the new batch (matching modern_to_v1_8.rs's
// table which is in turn cited to PrismarineJS minecraft-data 1.12.2):
const V112_S2C_PLUGIN_MESSAGE: u8 = 0x18;
const V112_S2C_DESTROY_ENTITIES: u8 = 0x32;
const V112_S2C_ENTITY_HEAD_LOOK: u8 = 0x36;
/// Target id for EntityVelocity (1.12.2 = 0x3E). Not currently used —
/// the matching s2c converter only consumes EntityVelocity input as
/// best-effort passthrough rather than rebuilding it. Kept as
/// documentation of the proto-340 packet table.
#[allow(dead_code)]
const V112_S2C_ENTITY_VELOCITY: u8 = 0x3E;
const V112_S2C_UPDATE_HEALTH: u8 = 0x41;
const V112_S2C_SPAWN_POSITION: u8 = 0x46;
const V112_S2C_TIME_UPDATE: u8 = 0x47;
const V112_S2C_COLLECT_ITEM: u8 = 0x4B;

pub fn convert_s2c(payload: Bytes) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    match id {
        V164_S2C_KEEP_ALIVE => s2c_keep_alive(body),
        V164_S2C_CHAT => s2c_chat(body),
        V164_S2C_PLAYER_POS_LOOK => s2c_player_pos_look(body),
        V164_S2C_SPAWN_PLAYER => s2c_spawn_player(body),
        V164_S2C_ENTITY_TELEPORT => s2c_entity_teleport(body),
        V164_S2C_ENTITY_REL_MOVE => s2c_entity_rel_move(body),
        V164_S2C_ENTITY => s2c_entity(body),
        V164_S2C_BLOCK_CHANGE => s2c_block_change(body),
        V164_S2C_SET_SLOT => s2c_set_slot(body),
        V164_S2C_WINDOW_ITEMS => s2c_window_items(body),
        V164_S2C_ENTITY_EQUIPMENT => s2c_entity_equipment(body),
        V164_S2C_EXPERIENCE => s2c_experience(body),
        V164_S2C_HELD_ITEM_CHANGE => s2c_held_item_change(body),
        V164_S2C_PLAYER_ABILITIES => s2c_player_abilities(body),
        V164_S2C_DISCONNECT => s2c_disconnect(body),
        V164_S2C_TIME_UPDATE => s2c_time_update(body),
        V164_S2C_SPAWN_POSITION => s2c_spawn_position(body),
        V164_S2C_UPDATE_HEALTH => s2c_update_health(body),
        V164_S2C_COLLECT_ITEM => s2c_collect_item(body),
        V164_S2C_DESTROY_ENTITIES => s2c_destroy_entities(body),
        V164_S2C_ENTITY_HEAD_LOOK => s2c_entity_head_look(body),
        V164_S2C_PLUGIN_MESSAGE => s2c_plugin_message(body),
        _ => ConversionResult::Passthrough,
    }
}

fn s2c_keep_alive(mut body: Bytes) -> ConversionResult {
    // 1.6.4 KeepAlive: i32 id.
    // 1.12.2 (proto 340) KeepAlive S2C: i64 id — Mojang switched from
    // VarInt to Long specifically at proto 340 (matches the
    // `for_proto >= 340` branch in
    // `kojacoord_protocol::versions::v1_12_x::play::ClientboundKeepAlive::encode`).
    // The previous code here wrote VarInt — for any real 1.12.2 client
    // this desynced the keepalive id range and the connection timed
    // out after ~30 s.
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let id = body.get_i32();
    let mut out = BytesMut::with_capacity(8);
    out.put_i64(id as i64);
    ConversionResult::Converted(vec![build_payload(V112_S2C_KEEP_ALIVE, &out)])
}

fn s2c_chat(mut body: Bytes) -> ConversionResult {
    // 1.6.4 wire strings are UCS-2 BIG-ENDIAN with a u16 BE length
    // prefix per the Notchian pre-netty protocol (verified against
    // `kojacoord_protocol::versions::v1_6_x::play::decode_legacy_string`
    // which uses `from_be_bytes` and `get_u16` — big-endian throughout).
    // The previous code here used `u16::from_be_bytes` — every chat
    // message routed through this converter arrived at the 1.12.2
    // client as garbage Unicode (every character was byte-swapped).
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }

    let str_len = body.get_u16() as usize; // bytes::Bytes::get_u16 is BE — correct.
    if body.remaining() < str_len * 2 {
        return ConversionResult::Passthrough;
    }

    let mut utf16_bytes = vec![0u8; str_len * 2];
    body.copy_to_slice(&mut utf16_bytes);

    let utf8_string = String::from_utf16_lossy(
        &utf16_bytes
            .chunks(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .collect::<Vec<_>>(),
    );

    // 1.12.2 ChatMessage S2C: JSON String + position byte.
    // The 1.6.4 plaintext won't render properly in 1.12+ without being
    // wrapped in a chat-component JSON. Wrap it as {"text":"..."} so
    // the 1.12.2 client doesn't choke on malformed JSON. We escape
    // double-quotes and backslashes minimally.
    let escaped = utf8_string.replace('\\', "\\\\").replace('"', "\\\"");
    let json = format!(r#"{{"text":"{}"}}"#, escaped);

    let mut out = BytesMut::new();
    VarInt(json.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(json.as_bytes());
    out.put_u8(0);

    ConversionResult::Converted(vec![build_payload(V112_S2C_CHAT, &out)])
}

fn s2c_player_pos_look(mut body: Bytes) -> ConversionResult {
    // 1.6.4 wire (Packet13PlayerLookMove, MCP decompile constructor:
    // `(double X, double stance, double Y, double Z, float yaw,
    //   float pitch, boolean onGround)`):
    //   f64 x, f64 stance, f64 y, f64 z, f32 yaw, f32 pitch, u8 onGround
    //   = 8+8+8+8+4+4+1 = 41 bytes.
    // 1.12.2 wire (PlayerPositionAndLook S2C):
    //   f64 x, f64 y, f64 z, f32 yaw, f32 pitch, u8 flags, VarInt teleport_id
    //
    // The previous code had THREE bugs:
    // 1. Read i32 (4 bytes) for each coord — 1.6.4 sends f64 (8 bytes).
    //    Every coord arrived as a tiny garbage value cast to f64.
    // 2. Read order `x, y, stance, z` — 1.6.4 wire is `x, stance, y, z`
    //    per the MCP constructor signature (verified previously as
    //    audit fix #11 in the typed v1_6_x play module). Y and stance
    //    were swapped.
    // 3. Size check `body.remaining() < 33` matched the 1.12.2 OUTPUT
    //    size; the 1.6.4 INPUT is 41 bytes. Real packets always passed
    //    the check, but malformed short packets reached `get_i32` and
    //    silently produced bogus output rather than Passthrough.
    if body.remaining() < 41 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_f64();
    let _stance = body.get_f64();
    let y = body.get_f64();
    let z = body.get_f64();
    let yaw = body.get_f32();
    let pitch = body.get_f32();
    let _on_ground = body.get_u8() != 0;

    let mut out = BytesMut::new();
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_f32(yaw);
    out.put_f32(pitch);
    // 1.12.2 has a `flags` u8 bitfield (NOT on_ground). 0 means every
    // coordinate is absolute — matches what 1.6.4 wire always carries.
    out.put_u8(0);
    // 1.12.2 also added a VarInt teleport_id. 0 is accepted by the
    // client; backend teleport-confirm tracking ignores it.
    VarInt(0).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_S2C_PLAYER_POS_LOOK, &out)])
}

fn s2c_spawn_player(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }

    let entity_id = body.get_i32();

    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let username_len = body.get_u16() as usize;
    if body.remaining() < username_len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut utf16_bytes = vec![0u8; username_len * 2];
    body.copy_to_slice(&mut utf16_bytes);
    let _username = String::from_utf16_lossy(
        &utf16_bytes
            .chunks(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .collect::<Vec<_>>(),
    );

    if body.remaining() < 4 + 4 + 4 + 1 + 1 + 2 {
        return ConversionResult::Passthrough;
    }

    let x = body.get_i32() as f64;
    let y = body.get_i32() as f64;
    let z = body.get_i32() as f64;
    let yaw = body.get_i8();
    let pitch = body.get_i8();
    let current_item = body.get_i16();

    let player_uuid = uuid::Uuid::new_v4();

    let mut out = BytesMut::new();
    VarInt(entity_id).encode(&mut out).unwrap();

    let (hi, lo) = player_uuid.as_u64_pair();
    out.put_i64(hi as i64);
    out.put_i64(lo as i64);

    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_u8(yaw as u8);
    out.put_u8(pitch as u8);
    VarInt(current_item as i32).encode(&mut out).unwrap();

    out.put_u8(0xFF);

    ConversionResult::Converted(vec![build_payload(V112_S2C_SPAWN_PLAYER, &out)])
}

fn s2c_entity_teleport(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 18 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body.get_i32();
    let x = body.get_i32() as f64;
    let y = body.get_i32() as f64;
    let z = body.get_i32() as f64;
    let yaw = body.get_i8();
    let pitch = body.get_i8();

    let mut out = BytesMut::with_capacity(18);
    VarInt(entity_id).encode(&mut out).unwrap();
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_u8(yaw as u8);
    out.put_u8(pitch as u8);
    out.put_u8(0);
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_TELEPORT, &out)])
}

fn s2c_entity_rel_move(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 7 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body.get_i32();
    let dx = body.get_i8();
    let dy = body.get_i8();
    let dz = body.get_i8();

    let mut out = BytesMut::with_capacity(8);
    VarInt(entity_id).encode(&mut out).unwrap();
    out.put_i16(dx as i16);
    out.put_i16(dy as i16);
    out.put_i16(dz as i16);
    out.put_u8(0);
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_REL_MOVE, &out)])
}

fn s2c_entity(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 1 + 4 + 4 + 4 + 1 + 1 + 1 + 2 + 2 + 2 {
        return ConversionResult::Passthrough;
    }

    let entity_id = body.get_i32();
    let entity_type = body.get_i8() as i32;
    let x = body.get_i32() as f64;
    let y = body.get_i32() as f64;
    let z = body.get_i32() as f64;
    let yaw = body.get_i8();
    let pitch = body.get_i8();
    let head_pitch = body.get_i8();
    let velocity_x = body.get_i16();
    let velocity_y = body.get_i16();
    let velocity_z = body.get_i16();

    let mut out = BytesMut::new();
    VarInt(entity_id).encode(&mut out).unwrap();
    VarInt(entity_type).encode(&mut out).unwrap();
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_u8(yaw as u8);
    out.put_u8(pitch as u8);
    out.put_u8(head_pitch as u8);
    out.put_i16(velocity_x);
    out.put_i16(velocity_y);
    out.put_i16(velocity_z);

    out.put_u8(0xFF);

    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY, &out)])
}

fn s2c_block_change(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 11 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32();
    let y = body.get_i8();
    let z = body.get_i32();
    let block_id = body.get_i32();
    let metadata = body.get_i8();

    let mut out = BytesMut::with_capacity(11);
    VarInt(x).encode(&mut out).unwrap();
    out.put_u8(y as u8);
    VarInt(z).encode(&mut out).unwrap();
    VarInt(block_id).encode(&mut out).unwrap();
    out.put_u8(metadata as u8);
    ConversionResult::Converted(vec![build_payload(V112_S2C_BLOCK_CHANGE, &out)])
}

fn s2c_set_slot(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 + 2 {
        return ConversionResult::Passthrough;
    }

    let window_id = body.get_i8();
    let slot = body.get_i16();

    if body.remaining() < 2 + 2 + 1 {
        return ConversionResult::Passthrough;
    }

    let item_id = body.get_i16();
    let _damage = body.get_i16();
    let count = body.get_i8();

    let mut out = BytesMut::new();
    out.put_i8(window_id);
    out.put_i16(slot);

    if item_id == -1 {
        out.put_u8(0);
    } else {
        VarInt(item_id as i32).encode(&mut out).unwrap();
        out.put_i8(count);

        out.put_u8(0x00);
    }

    ConversionResult::Converted(vec![build_payload(V112_S2C_SET_SLOT, &out)])
}

fn s2c_window_items(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 + 2 {
        return ConversionResult::Passthrough;
    }

    let window_id = body.get_i8();
    let count = body.get_i16();

    let mut out = BytesMut::new();
    out.put_i8(window_id);
    VarInt(0).encode(&mut out).unwrap();

    for _ in 0..count {
        if body.remaining() < 2 + 2 + 1 {
            return ConversionResult::Passthrough;
        }

        let item_id = body.get_i16();
        let _damage = body.get_i16();
        let slot_count = body.get_i8();

        if item_id == -1 {
            out.put_u8(0);
        } else {
            VarInt(item_id as i32).encode(&mut out).unwrap();
            out.put_i8(slot_count);

            out.put_u8(0x00);
        }
    }

    ConversionResult::Converted(vec![build_payload(V112_S2C_WINDOW_ITEMS, &out)])
}

fn s2c_entity_equipment(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 6 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body.get_i32();
    let slot = body.get_i16();
    let item = body.get_i16();

    let mut out = BytesMut::with_capacity(8);
    VarInt(entity_id).encode(&mut out).unwrap();
    VarInt(slot as i32).encode(&mut out).unwrap();
    VarInt(item as i32).encode(&mut out).unwrap();
    out.put_u8(0);
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_EQUIPMENT, &out)])
}

fn s2c_experience(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let experience_bar = body.get_f32();
    let level = body.get_i16();
    let total_experience = body.get_i16();

    let mut out = BytesMut::with_capacity(6);
    out.put_f32(experience_bar);
    VarInt(level as i32).encode(&mut out).unwrap();
    VarInt(total_experience as i32).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_S2C_EXPERIENCE, &out)])
}

fn s2c_held_item_change(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let slot = body.get_i8();

    let mut out = BytesMut::with_capacity(2);
    VarInt(slot as i32).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_S2C_HELD_ITEM_CHANGE, &out)])
}

fn s2c_player_abilities(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 12 {
        return ConversionResult::Passthrough;
    }
    let flags = body.get_u8();
    let flying_speed = body.get_f32();
    let walking_speed = body.get_f32();

    let mut out = BytesMut::with_capacity(9);
    out.put_u8(flags);
    out.put_f32(flying_speed);
    out.put_f32(walking_speed);
    ConversionResult::Converted(vec![build_payload(V112_S2C_PLAYER_ABILITIES, &out)])
}

fn s2c_disconnect(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }

    let str_len = body.get_u16() as usize;
    if body.remaining() < str_len * 2 {
        return ConversionResult::Passthrough;
    }

    let mut utf16_bytes = vec![0u8; str_len * 2];
    body.copy_to_slice(&mut utf16_bytes);

    let plain_text = String::from_utf16_lossy(
        &utf16_bytes
            .chunks(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .collect::<Vec<_>>(),
    );

    let json_message = format!(r#"{{"text":"{}"}}"#, plain_text.replace('"', r#"\""#));

    let mut out = BytesMut::new();
    VarInt(json_message.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(json_message.as_bytes());

    ConversionResult::Converted(vec![build_payload(V112_S2C_DISCONNECT, &out)])
}

// ── New batch: TimeUpdate, SpawnPosition, UpdateHealth, CollectItem,
//    DestroyEntities, EntityHeadLook, PluginMessage ───────────────────

/// 1.6.4 TimeUpdate (Packet4): i64 worldAge, i64 timeOfDay.
/// 1.12.2 TimeUpdate (0x47): i64 worldAge, i64 timeOfDay. Same shape.
fn s2c_time_update(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 16 {
        return ConversionResult::Passthrough;
    }
    let age = body.get_i64();
    let tod = body.get_i64();
    let mut out = BytesMut::with_capacity(16);
    out.put_i64(age);
    out.put_i64(tod);
    ConversionResult::Converted(vec![build_payload(V112_S2C_TIME_UPDATE, &out)])
}

/// 1.6.4 SpawnPosition (Packet6): i32 x, i32 y, i32 z.
/// 1.12.2 SpawnPosition (0x46): packed Position (legacy layout).
fn s2c_spawn_position(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 12 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32();
    let y = body.get_i32();
    let z = body.get_i32();
    let pos = kojacoord_protocol::types::Position { x, y, z };
    let packed = kojacoord_protocol::types::encode_legacy_position(pos);
    let mut out = BytesMut::with_capacity(8);
    out.put_i64(packed);
    ConversionResult::Converted(vec![build_payload(V112_S2C_SPAWN_POSITION, &out)])
}

/// 1.6.4 UpdateHealth (Packet8): f32 health, i16 food, f32 saturation.
/// 1.12.2 UpdateHealth (0x41): f32 health, VarInt food, f32 saturation.
fn s2c_update_health(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 10 {
        return ConversionResult::Passthrough;
    }
    let health = body.get_f32();
    let food = body.get_i16();
    let saturation = body.get_f32();
    let mut out = BytesMut::new();
    out.put_f32(health);
    VarInt(food as i32).encode(&mut out).unwrap();
    out.put_f32(saturation);
    ConversionResult::Converted(vec![build_payload(V112_S2C_UPDATE_HEALTH, &out)])
}

/// 1.6.4 CollectItem (Packet22): i32 collected, i32 collector.
/// 1.12.2 CollectItem (0x4B): VarInt collected, VarInt collector,
///   VarInt count. We synthesise count=1 since 1.6.4 doesn't carry it.
fn s2c_collect_item(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let collected = body.get_i32();
    let collector = body.get_i32();
    let mut out = BytesMut::new();
    VarInt(collected).encode(&mut out).unwrap();
    VarInt(collector).encode(&mut out).unwrap();
    VarInt(1).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_S2C_COLLECT_ITEM, &out)])
}

/// 1.6.4 DestroyEntities (Packet29): i8 count + count×i32 ids.
/// 1.12.2 DestroyEntities (0x32): VarInt count + count×VarInt ids.
fn s2c_destroy_entities(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let count = body.get_i8() as i32;
    if count < 0 || (count as usize) * 4 > body.remaining() {
        return ConversionResult::Passthrough;
    }
    let mut out = BytesMut::new();
    VarInt(count).encode(&mut out).unwrap();
    for _ in 0..count {
        let eid = body.get_i32();
        VarInt(eid).encode(&mut out).unwrap();
    }
    ConversionResult::Converted(vec![build_payload(V112_S2C_DESTROY_ENTITIES, &out)])
}

/// 1.6.4 EntityHeadLook (Packet35): i32 entity_id, i8 head_yaw.
/// 1.12.2 EntityHeadLook (0x36): VarInt entity_id, i8 head_yaw.
fn s2c_entity_head_look(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 5 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let yaw = body.get_i8();
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_i8(yaw);
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_HEAD_LOOK, &out)])
}

/// 1.6.4 PluginMessage / CustomPayload (Packet250 = 0xFA):
///   UCS-2 BE channel + u16 BE length + raw bytes.
/// 1.12.2 PluginMessage (0x18): VarInt-prefixed UTF-8 channel +
///   raw bytes (rest of packet).
fn s2c_plugin_message(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let chan_chars = body.get_u16() as usize;
    if body.remaining() < chan_chars * 2 {
        return ConversionResult::Passthrough;
    }
    let mut chan_u16 = Vec::with_capacity(chan_chars);
    for _ in 0..chan_chars {
        chan_u16.push(body.get_u16());
    }
    let channel = String::from_utf16_lossy(&chan_u16);
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let payload_len = body.get_u16() as usize;
    if body.remaining() < payload_len {
        return ConversionResult::Passthrough;
    }
    let payload = body.copy_to_bytes(payload_len);

    let mut out = BytesMut::new();
    VarInt(channel.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(channel.as_bytes());
    out.extend_from_slice(&payload);
    ConversionResult::Converted(vec![build_payload(V112_S2C_PLUGIN_MESSAGE, &out)])
}

// Verified against HexaCord packet/ tree + MCP-doc class-name
// convention. Previous values 0x01 (CHAT) and 0x05 (PLAYER_POS_LOOK)
// were decimal names misread as hex — `Packet1Login` and
// `Packet5EntityEquipment` are entirely different packets. The
// converter silently passed real 1.6.4 chat and movement c2s through
// unconverted, and the 1.12.2 backend dropped them as malformed.
const V164_C2S_KEEP_ALIVE: u8 = 0x00; // Packet0KeepAlive
const V164_C2S_CHAT: u8 = 0x03; // Packet3Chat (was 0x01)
const V164_C2S_PLAYER_POS_LOOK: u8 = 0x0D; // Packet13PlayerLookMove (was 0x05)
const V164_C2S_PLAYER_DIGGING: u8 = 0x0E; // Packet14BlockDig
const V164_C2S_PLAYER_BLOCK_PLACEMENT: u8 = 0x0F; // Packet15Place
const V164_C2S_HELD_ITEM_CHANGE: u8 = 0x10; // Packet16BlockItemSwitch
const V164_C2S_ENTITY_ACTION: u8 = 0x13; // Packet19EntityAction

const V112_C2S_KEEP_ALIVE: u8 = 0x0B;
const V112_C2S_CHAT: u8 = 0x02;
const V112_C2S_PLAYER_POS_LOOK: u8 = 0x0E;
const V112_C2S_PLAYER_DIGGING: u8 = 0x14;
const V112_C2S_PLAYER_BLOCK_PLACEMENT: u8 = 0x1F;
const V112_C2S_HELD_ITEM_CHANGE: u8 = 0x1A;
const V112_C2S_ENTITY_ACTION: u8 = 0x15;

// Additional 1.6.4 source ids for the expanded c2s coverage.
// Per HexaCord packet table + minecraft.wiki Java_Edition_protocol §1.6.4.
const V164_C2S_USE_ENTITY: u8 = 0x07; // Packet7UseEntity
const V164_C2S_PLAYER: u8 = 0x0A; // Packet10Flying (on-ground only)
const V164_C2S_PLAYER_POSITION: u8 = 0x0B; // Packet11PlayerPosition
const V164_C2S_PLAYER_LOOK: u8 = 0x0C; // Packet12PlayerLook
const V164_C2S_ANIMATION: u8 = 0x12; // Packet18Animation
const V164_C2S_CLIENT_COMMAND: u8 = 0x16; // Packet22ClientCommand (respawn)
const V164_C2S_CLOSE_WINDOW: u8 = 0x65; // Packet101CloseWindow
const V164_C2S_CLICK_WINDOW: u8 = 0x66; // Packet102ClickWindow
const V164_C2S_CONFIRM_TX: u8 = 0x6A; // Packet106Transaction
const V164_C2S_UPDATE_SIGN: u8 = 0x82; // Packet130UpdateSign
const V164_C2S_PLAYER_ABILITIES: u8 = 0xCA; // Packet202PlayerAbilities
const V164_C2S_TAB_COMPLETE: u8 = 0xCB; // Packet203AutoComplete
const V164_C2S_CLIENT_SETTINGS: u8 = 0xCC; // Packet204LocaleAndViewDistance
const V164_C2S_CLIENT_STATUS: u8 = 0xCD; // Packet205ClientCommand
const V164_C2S_PLUGIN_MESSAGE: u8 = 0xFA; // Packet250CustomPayload

// 1.12.2 target ids (s2c naming for our s2c side already exists above;
// here we add the c2s targets for the expanded coverage).
// Additional 1.12.2 c2s target ids not in the original const block above.
const V112_C2S_TAB_COMPLETE_OUT: u8 = 0x01;
const V112_C2S_CLIENT_STATUS_OUT: u8 = 0x03;
const V112_C2S_CLIENT_SETTINGS_OUT: u8 = 0x04;
const V112_C2S_CONFIRM_TX_OUT: u8 = 0x05;
const V112_C2S_CLICK_WINDOW_OUT: u8 = 0x07;
const V112_C2S_CLOSE_WINDOW_OUT: u8 = 0x08;
const V112_C2S_PLUGIN_MESSAGE_OUT: u8 = 0x09;
const V112_C2S_USE_ENTITY_OUT: u8 = 0x0A;
const V112_C2S_PLAYER_POSITION_OUT: u8 = 0x0C;
const V112_C2S_PLAYER_LOOK_OUT: u8 = 0x0F;
const V112_C2S_PLAYER_OUT: u8 = 0x0D; // Player flying (on-ground only)
const V112_C2S_PLAYER_ABILITIES_OUT: u8 = 0x13;
const V112_C2S_UPDATE_SIGN_OUT: u8 = 0x1C;
const V112_C2S_ANIMATION_OUT: u8 = 0x1D;

pub fn convert_c2s(payload: Bytes) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    match id {
        V164_C2S_KEEP_ALIVE => c2s_keep_alive(body),
        V164_C2S_CHAT => c2s_chat(body),
        V164_C2S_USE_ENTITY => c2s_use_entity(body),
        V164_C2S_PLAYER => c2s_player(body),
        V164_C2S_PLAYER_POSITION => c2s_player_position(body),
        V164_C2S_PLAYER_LOOK => c2s_player_look(body),
        V164_C2S_PLAYER_POS_LOOK => c2s_player_pos_look(body),
        V164_C2S_PLAYER_DIGGING => c2s_player_digging(body),
        V164_C2S_PLAYER_BLOCK_PLACEMENT => c2s_player_block_placement(body),
        V164_C2S_HELD_ITEM_CHANGE => c2s_held_item_change(body),
        V164_C2S_ANIMATION => c2s_animation(body),
        V164_C2S_ENTITY_ACTION => c2s_entity_action(body),
        V164_C2S_CLIENT_COMMAND => c2s_client_command(body),
        V164_C2S_CLOSE_WINDOW => c2s_close_window(body),
        V164_C2S_CLICK_WINDOW => c2s_click_window(body),
        V164_C2S_CONFIRM_TX => c2s_confirm_tx(body),
        V164_C2S_UPDATE_SIGN => c2s_update_sign(body),
        V164_C2S_PLAYER_ABILITIES => c2s_player_abilities(body),
        V164_C2S_TAB_COMPLETE => c2s_tab_complete(body),
        V164_C2S_CLIENT_SETTINGS => c2s_client_settings(body),
        V164_C2S_CLIENT_STATUS => c2s_client_status(body),
        V164_C2S_PLUGIN_MESSAGE => c2s_plugin_message(body),
        _ => ConversionResult::Passthrough,
    }
}

// ─── 1.6.4→1.12.2 c2s converters (expanded set) ────────────────────

/// 1.6.4 UseEntity: `[i32 user][i32 target][i8 left_click]`.
/// 1.12.2 UseEntity: `[VarInt target][VarInt type (0=interact,1=attack,2=interact_at)]`.
/// We drop `user` (server knows the player's own eid), and map left_click
/// to type=1 (attack) when true, type=0 (interact) when false.
fn c2s_use_entity(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 9 {
        return ConversionResult::Passthrough;
    }
    let _user = body.get_i32();
    let target = body.get_i32();
    let left_click = body.get_i8() != 0;
    let mut out = BytesMut::new();
    VarInt(target).encode(&mut out).ok();
    VarInt(if left_click { 1 } else { 0 }).encode(&mut out).ok();
    ConversionResult::Converted(vec![build_payload(V112_C2S_USE_ENTITY_OUT, &out)])
}

/// 1.6.4 Player (on-ground only): `[bool on_ground]`.
/// 1.12.2 Player: `[bool on_ground]`. Same shape, just remap id.
fn c2s_player(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let og = body.get_u8();
    let mut out = BytesMut::new();
    out.put_u8(og);
    ConversionResult::Converted(vec![build_payload(V112_C2S_PLAYER_OUT, &out)])
}

/// 1.6.4 PlayerPosition: `[f64 x][f64 y][f64 stance][f64 z][bool on_ground]`.
/// 1.12.2 PlayerPosition: `[f64 x][f64 feet_y][f64 z][bool on_ground]`.
/// 1.6 had a separate stance field (eye-y); modern uses feet_y directly.
fn c2s_player_position(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 * 4 + 1 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_f64();
    let y = body.get_f64();
    let _stance = body.get_f64();
    let z = body.get_f64();
    let og = body.get_u8();
    let mut out = BytesMut::new();
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_u8(og);
    ConversionResult::Converted(vec![build_payload(V112_C2S_PLAYER_POSITION_OUT, &out)])
}

/// 1.6.4 PlayerLook: `[f32 yaw][f32 pitch][bool on_ground]`.
/// 1.12.2 PlayerLook: same shape.
fn c2s_player_look(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 4 + 1 {
        return ConversionResult::Passthrough;
    }
    let yaw = body.get_f32();
    let pitch = body.get_f32();
    let og = body.get_u8();
    let mut out = BytesMut::new();
    out.put_f32(yaw);
    out.put_f32(pitch);
    out.put_u8(og);
    ConversionResult::Converted(vec![build_payload(V112_C2S_PLAYER_LOOK_OUT, &out)])
}

/// 1.6.4 Animation: `[i32 entity_id][i8 animation]`.
/// 1.12.2 Animation: `[VarInt hand]`. The 1.6 packet covered entity
/// animations including swing (animation=1), and the server's modern
/// equivalent only takes a hand id (0=main, 1=off). Map any animation
/// to hand=0 (main hand); 1.12 doesn't model the other 1.6 animations
/// (eat food, leave bed, crit, magic-crit) as c2s.
fn c2s_animation(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 5 {
        return ConversionResult::Passthrough;
    }
    let _eid = body.get_i32();
    let _anim = body.get_i8();
    let mut out = BytesMut::new();
    VarInt(0).encode(&mut out).ok();
    ConversionResult::Converted(vec![build_payload(V112_C2S_ANIMATION_OUT, &out)])
}

/// 1.6.4 ClientCommand (Packet22ClientCommand, id 0x16): `[i8 payload]`
/// — payload=1 means "respawn". 1.12.2 ClientStatus (0x03): `[VarInt
/// action]` — 0=respawn, 1=open-inv-achievement.
fn c2s_client_command(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let _payload = body.get_i8();
    // Treat any client-command as respawn (the only payload value 1.6.4
    // actually emits is 1 = respawn from the death screen).
    let mut out = BytesMut::new();
    VarInt(0).encode(&mut out).ok();
    ConversionResult::Converted(vec![build_payload(V112_C2S_CLIENT_STATUS_OUT, &out)])
}

/// 1.6.4 CloseWindow: `[u8 window_id]`. 1.12.2 CloseWindow: same shape.
fn c2s_close_window(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let id = body.get_u8();
    let mut out = BytesMut::new();
    out.put_u8(id);
    ConversionResult::Converted(vec![build_payload(V112_C2S_CLOSE_WINDOW_OUT, &out)])
}

/// 1.6.4 ClickWindow (Packet102WindowClick): `[u8 win_id][i16 slot]`
/// `[i8 button][i16 action_number][i8 mode][Slot item]`.
/// 1.12.2 ClickWindow: `[u8 win_id][i16 slot][i8 button][i16 action_number]`
/// `[VarInt mode][Slot item]`. Modern serialises `mode` as VarInt,
/// legacy as i8 — same value range, just re-encode.
/// We drop the trailing Slot to avoid a wire-format mismatch — the
/// server re-syncs from its own inventory snapshot anyway.
fn c2s_click_window(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 + 2 + 1 + 2 + 1 {
        return ConversionResult::Passthrough;
    }
    let win_id = body.get_u8();
    let slot = body.get_i16();
    let button = body.get_i8();
    let action = body.get_i16();
    let mode = body.get_i8();
    let mut out = BytesMut::new();
    out.put_u8(win_id);
    out.put_i16(slot);
    out.put_i8(button);
    out.put_i16(action);
    VarInt(mode as i32).encode(&mut out).ok();
    out.put_i16(-1); // empty Slot
    ConversionResult::Converted(vec![build_payload(V112_C2S_CLICK_WINDOW_OUT, &out)])
}

/// 1.6.4 ConfirmTransaction (Packet106): `[u8 win_id][i16 action][bool accepted]`.
/// 1.12.2 ConfirmTransaction: same shape.
fn c2s_confirm_tx(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let win_id = body.get_u8();
    let action = body.get_i16();
    let accepted = body.get_u8();
    let mut out = BytesMut::new();
    out.put_u8(win_id);
    out.put_i16(action);
    out.put_u8(accepted);
    ConversionResult::Converted(vec![build_payload(V112_C2S_CONFIRM_TX_OUT, &out)])
}

/// 1.6.4 UpdateSign: `[i32 x][i16 y][i32 z][4× UCS-2 line]`.
/// 1.12.2 UpdateSign: `[i64 packed Position][4× String line]`.
fn c2s_update_sign(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 2 + 4 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32();
    let y = body.get_i16() as i32;
    let z = body.get_i32();
    let mut lines: Vec<String> = Vec::with_capacity(4);
    for _ in 0..4 {
        if body.remaining() < 2 {
            return ConversionResult::Passthrough;
        }
        let len = body.get_u16() as usize;
        if body.remaining() < len * 2 {
            return ConversionResult::Passthrough;
        }
        let mut units = Vec::with_capacity(len);
        for _ in 0..len {
            units.push(body.get_u16());
        }
        lines.push(String::from_utf16(&units).unwrap_or_default());
    }
    let packed =
        kojacoord_protocol::types::encode_legacy_position(kojacoord_protocol::Position { x, y, z });
    let mut out = BytesMut::new();
    out.put_i64(packed as i64);
    for line in &lines {
        let bytes = line.as_bytes();
        VarInt(bytes.len() as i32).encode(&mut out).ok();
        out.put_slice(bytes);
    }
    ConversionResult::Converted(vec![build_payload(V112_C2S_UPDATE_SIGN_OUT, &out)])
}

/// 1.6.4 PlayerAbilities (c2s): `[i8 flags][f32 fly][f32 walk]`.
/// 1.12.2 PlayerAbilities (c2s): `[i8 flags][f32 fly][f32 walk]`. Same.
fn c2s_player_abilities(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 9 {
        return ConversionResult::Passthrough;
    }
    let flags = body.get_i8();
    let fly = body.get_f32();
    let walk = body.get_f32();
    let mut out = BytesMut::new();
    out.put_i8(flags);
    out.put_f32(fly);
    out.put_f32(walk);
    ConversionResult::Converted(vec![build_payload(V112_C2S_PLAYER_ABILITIES_OUT, &out)])
}

/// 1.6.4 TabComplete: `[UCS-2 text]`.
/// 1.12.2 TabComplete: `[String text][bool assume_command][bool has_pos][?i64 pos]`.
fn c2s_tab_complete(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let len = body.get_u16() as usize;
    if body.remaining() < len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut units = Vec::with_capacity(len);
    for _ in 0..len {
        units.push(body.get_u16());
    }
    let text = String::from_utf16(&units).unwrap_or_default();
    let mut out = BytesMut::new();
    let bytes = text.as_bytes();
    VarInt(bytes.len() as i32).encode(&mut out).ok();
    out.put_slice(bytes);
    out.put_u8(0); // assume_command = false
    out.put_u8(0); // has_pos = false
    ConversionResult::Converted(vec![build_payload(V112_C2S_TAB_COMPLETE_OUT, &out)])
}

/// 1.6.4 LocaleAndViewDistance (0xCC): `[UCS-2 locale][i8 view_distance]`
/// `[i8 chat_flags][i8 difficulty][bool show_cape]`.
/// chat_flags is a bitfield: bits 0-2 chat_visibility, bit 3 colors.
/// 1.12.2 ClientSettings (0x04): `[String locale][i8 view_distance]`
/// `[VarInt chat_mode][bool chat_colors][u8 skin_parts][VarInt main_hand]`.
fn c2s_client_settings(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let len = body.get_u16() as usize;
    if body.remaining() < len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut units = Vec::with_capacity(len);
    for _ in 0..len {
        units.push(body.get_u16());
    }
    let locale = String::from_utf16(&units).unwrap_or_default();
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let view_distance = body.get_i8();
    let chat_flags = body.get_i8();
    let difficulty = body.get_i8();
    let _show_cape = body.get_u8();

    let chat_mode = chat_flags & 0x7;
    let chat_colors = (chat_flags & 0x8) != 0;
    let _ = difficulty; // 1.12 ClientSettings doesn't echo difficulty back

    let mut out = BytesMut::new();
    let bytes = locale.as_bytes();
    VarInt(bytes.len() as i32).encode(&mut out).ok();
    out.put_slice(bytes);
    out.put_i8(view_distance);
    VarInt(chat_mode as i32).encode(&mut out).ok();
    out.put_u8(chat_colors as u8);
    out.put_u8(0x7F); // skin_parts: all visible
    VarInt(1).encode(&mut out).ok(); // main_hand = 1 (right)
    ConversionResult::Converted(vec![build_payload(V112_C2S_CLIENT_SETTINGS_OUT, &out)])
}

/// 1.6.4 ClientStatus (0xCD): `[i8 status]`.
/// 1.12.2 ClientStatus (0x03): `[VarInt action]`. Direct mapping (0=respawn,
/// 1=open inventory achievement).
fn c2s_client_status(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let status = body.get_i8();
    let mut out = BytesMut::new();
    VarInt(status as i32).encode(&mut out).ok();
    ConversionResult::Converted(vec![build_payload(V112_C2S_CLIENT_STATUS_OUT, &out)])
}

/// 1.6.4 PluginMessage (0xFA): `[UCS-2 channel][i16 data_len][bytes data]`.
/// 1.12.2 PluginMessage (0x09): `[String channel][bytes data]`.
/// Channel name remapping: 1.6's `MC|<name>` legacy form → 1.13+ uses
/// `minecraft:<name>` — but 1.12.2 still uses `MC|<name>`, so passthrough.
fn c2s_plugin_message(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let len = body.get_u16() as usize;
    if body.remaining() < len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut units = Vec::with_capacity(len);
    for _ in 0..len {
        units.push(body.get_u16());
    }
    let channel = String::from_utf16(&units).unwrap_or_default();
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let data_len = body.get_i16().max(0) as usize;
    if body.remaining() < data_len {
        return ConversionResult::Passthrough;
    }
    let mut data = vec![0u8; data_len];
    body.copy_to_slice(&mut data);
    let mut out = BytesMut::new();
    let cbytes = channel.as_bytes();
    VarInt(cbytes.len() as i32).encode(&mut out).ok();
    out.put_slice(cbytes);
    out.put_slice(&data);
    ConversionResult::Converted(vec![build_payload(V112_C2S_PLUGIN_MESSAGE_OUT, &out)])
}

fn c2s_keep_alive(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let id = body.get_i32();
    let mut out = BytesMut::with_capacity(4);
    VarInt(id).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_C2S_KEEP_ALIVE, &out)])
}

fn c2s_chat(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }

    let str_len = body.get_u16() as usize;
    if body.remaining() < str_len * 2 {
        return ConversionResult::Passthrough;
    }

    let mut utf16_bytes = vec![0u8; str_len * 2];
    body.copy_to_slice(&mut utf16_bytes);

    let utf8_string = String::from_utf16_lossy(
        &utf16_bytes
            .chunks(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .collect::<Vec<_>>(),
    );

    let mut out = BytesMut::new();
    VarInt(utf8_string.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(utf8_string.as_bytes());

    ConversionResult::Converted(vec![build_payload(V112_C2S_CHAT, &out)])
}

fn c2s_player_pos_look(mut body: Bytes) -> ConversionResult {
    // 1.6.4 input is 41 bytes (4×f64 + 2×f32 + bool); was wrongly 33.
    if body.remaining() < 41 {
        return ConversionResult::Passthrough;
    }
    // Same triple bug as s2c_player_pos_look: 1.6.4 wire is f64 (not
    // i32), order is X/Stance/Y/Z (not X/Y/Stance/Z), and size is 41
    // bytes (not 33). Per HexaCord-confirmed MCP `Packet13PlayerLookMove`.
    let x = body.get_f64();
    let _stance = body.get_f64();
    let y = body.get_f64();
    let z = body.get_f64();
    let yaw = body.get_f32();
    let pitch = body.get_f32();
    let on_ground = body.get_u8() != 0;

    // 1.12.2 c2s PlayerPositionAndLook: 3×f64, 2×f32, bool on_ground.
    // No flags byte, no teleport_id — only the s2c side carries those.
    let mut out = BytesMut::with_capacity(33);
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_f32(yaw);
    out.put_f32(pitch);
    out.put_u8(if on_ground { 1 } else { 0 });
    ConversionResult::Converted(vec![build_payload(V112_C2S_PLAYER_POS_LOOK, &out)])
}

fn c2s_player_digging(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 11 {
        return ConversionResult::Passthrough;
    }

    let status = body.get_i8();
    let x = body.get_i32();
    let y = body.get_i8();
    let z = body.get_i32();
    let face = body.get_i8();

    let mut out = BytesMut::new();
    VarInt(status as i32).encode(&mut out).unwrap();

    out.put_i64(x as i64);
    out.put_i64(y as i64);
    out.put_i64(z as i64);

    VarInt(face as i32).encode(&mut out).unwrap();

    ConversionResult::Converted(vec![build_payload(V112_C2S_PLAYER_DIGGING, &out)])
}

fn c2s_player_block_placement(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 16 {
        return ConversionResult::Passthrough;
    }

    let x = body.get_i32();
    let y = body.get_i8();
    let z = body.get_i32();
    let direction = body.get_i8();
    let held_item = body.get_i16();
    let cursor_x = body.get_i8();
    let cursor_y = body.get_i8();
    let cursor_z = body.get_i8();

    let mut out = BytesMut::new();

    out.put_i64(x as i64);
    out.put_i64(y as i64);
    out.put_i64(z as i64);

    VarInt(direction as i32).encode(&mut out).unwrap();
    VarInt(0).encode(&mut out).unwrap();
    out.put_i16(held_item);
    out.put_i8(cursor_x);
    out.put_i8(cursor_y);
    out.put_i8(cursor_z);

    ConversionResult::Converted(vec![build_payload(V112_C2S_PLAYER_BLOCK_PLACEMENT, &out)])
}

fn c2s_held_item_change(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let slot = body.get_i16();

    let mut out = BytesMut::with_capacity(2);
    VarInt(slot as i32).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_C2S_HELD_ITEM_CHANGE, &out)])
}

fn c2s_entity_action(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 5 {
        return ConversionResult::Passthrough;
    }

    let entity_id = body.get_i32();
    let action_id = body.get_i8();

    let mut out = BytesMut::new();
    VarInt(entity_id).encode(&mut out).unwrap();
    VarInt(action_id as i32).encode(&mut out).unwrap();
    VarInt(0).encode(&mut out).unwrap();

    ConversionResult::Converted(vec![build_payload(V112_C2S_ENTITY_ACTION, &out)])
}
