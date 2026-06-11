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

pub fn convert_c2s(payload: Bytes) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    match id {
        V164_C2S_KEEP_ALIVE => c2s_keep_alive(body),
        V164_C2S_CHAT => c2s_chat(body),
        V164_C2S_PLAYER_POS_LOOK => c2s_player_pos_look(body),
        V164_C2S_PLAYER_DIGGING => c2s_player_digging(body),
        V164_C2S_PLAYER_BLOCK_PLACEMENT => c2s_player_block_placement(body),
        V164_C2S_HELD_ITEM_CHANGE => c2s_held_item_change(body),
        V164_C2S_ENTITY_ACTION => c2s_entity_action(body),
        _ => ConversionResult::Passthrough,
    }
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
