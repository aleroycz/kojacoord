use bytes::{Buf, BufMut, Bytes, BytesMut};
use kojacoord_protocol::codec::{Decode, Encode};
use kojacoord_protocol::types::VarInt;
use kojacoord_protocol::{encode_modern_position, BlockFlatteningTable};

use super::helpers::rebuild_with_id;
use super::items;
use super::{build_payload, split_id};
use crate::converter::ConversionResult;

// Per the Notchian 1.6.4 pre-netty packet table (MCP-doc convention
// `Packet<N><Name>` — N decimal = hex id). Same two bugs as in
// `v1_6_4_to_v1_12_2.rs` fixed in lock-step: PLAYER_POS_LOOK was 0x13
// (= Packet19EntityAction) and HELD_ITEM_CHANGE was 0x09 (= Packet9
// Respawn). Correct values:
const V164_S2C_KEEP_ALIVE: u8 = 0x00; // Packet0KeepAlive
const V164_S2C_CHAT: u8 = 0x03; // Packet3Chat
const V164_S2C_PLAYER_POS_LOOK: u8 = 0x0D; // Packet13PlayerLookMove (was 0x13)
const V164_S2C_SPAWN_PLAYER: u8 = 0x14; // Packet20NamedEntitySpawn
const V164_S2C_ENTITY_TELEPORT: u8 = 0x22; // Packet34EntityTeleport
const V164_S2C_ENTITY_REL_MOVE: u8 = 0x15; // Packet21EntityRelativeMove
const V164_S2C_ENTITY: u8 = 0x1E; // Packet30Entity
const V164_S2C_BLOCK_CHANGE: u8 = 0x35; // Packet53BlockChange
const V164_S2C_SET_SLOT: u8 = 0x67; // Packet103SetSlot
const V164_S2C_WINDOW_ITEMS: u8 = 0x68; // Packet104WindowItems
const V164_S2C_ENTITY_EQUIPMENT: u8 = 0x1C; // Packet28EntityEquipment
const V164_S2C_EXPERIENCE: u8 = 0x2B; // Packet43Experience
const V164_S2C_HELD_ITEM_CHANGE: u8 = 0x10; // Packet16BlockItemSwitch (was 0x09)
const V164_S2C_PLAYER_ABILITIES: u8 = 0x43; // Packet67PlayerAbilities
const V164_S2C_DISCONNECT: u8 = 0xFF; // Packet255KickDisconnect

const V165_S2C_KEEP_ALIVE: u8 = 0x1F;
const V165_S2C_CHAT: u8 = 0x0E;
const V165_S2C_PLAYER_POS_LOOK: u8 = 0x34;
const V165_S2C_SPAWN_PLAYER: u8 = 0x04;
const V165_S2C_ENTITY_TELEPORT: u8 = 0x56;
const V165_S2C_ENTITY_REL_MOVE: u8 = 0x27;
const V165_S2C_ENTITY: u8 = 0x00;
const V165_S2C_BLOCK_CHANGE: u8 = 0x0B;
const V165_S2C_SET_SLOT: u8 = 0x15;
const V165_S2C_WINDOW_ITEMS: u8 = 0x13;
const V165_S2C_ENTITY_EQUIPMENT: u8 = 0x47;
const V165_S2C_EXPERIENCE: u8 = 0x48;
const V165_S2C_HELD_ITEM_CHANGE: u8 = 0x3F;
const V165_S2C_PLAYER_ABILITIES: u8 = 0x2F;
const V165_S2C_DISCONNECT: u8 = 0x19;

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
        _ => ConversionResult::Passthrough,
    }
}

fn s2c_keep_alive(mut body: Bytes) -> ConversionResult {
    // 1.6.4 KeepAlive: i32 id.
    // 1.16.5 (proto 754) KeepAlive S2C: i64 id — Mojang switched from
    // VarInt to Long at proto 340 (1.12.2) per BungeeCord
    // `Protocol.java::TO_CLIENT` KeepAlive table; every proto ≥ 340
    // including 754 carries the Long shape.
    // The previous code wrote two VarInts — total garbage shape that
    // every 1.16.5 client misparsed → ~30s timeout disconnect.
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let id = body.get_i32();
    let mut out = BytesMut::with_capacity(8);
    out.put_i64(id as i64);
    ConversionResult::Converted(vec![build_payload(V165_S2C_KEEP_ALIVE, &out)])
}

fn s2c_chat(mut body: Bytes) -> ConversionResult {
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
    out.put_u8(0);

    let nil_uuid = uuid::Uuid::nil();
    let (hi, lo) = nil_uuid.as_u64_pair();
    out.put_i64(hi as i64);
    out.put_i64(lo as i64);

    ConversionResult::Converted(vec![build_payload(V165_S2C_CHAT, &out)])
}

fn s2c_player_pos_look(mut body: Bytes) -> ConversionResult {
    // 1.6.4 wire (Packet13PlayerLookMove): f64 x, f64 stance, f64 y,
    // f64 z, f32 yaw, f32 pitch, u8 onGround = 41 bytes.
    // 1.16.5 wire (PlayerPositionAndLook S2C): f64 x, f64 y, f64 z,
    // f32 yaw, f32 pitch, u8 flags, VarInt teleport_id.
    //
    // Same triple bug as v1_6_4_to_v1_12_2::s2c_player_pos_look:
    // i32 reads (should be f64), wrong field order (Y/stance swapped),
    // wrong size check (33 vs 41). 1.16.5 ALSO requires the trailing
    // VarInt teleport_id which was being omitted entirely → either
    // disconnect or arrival at (0, 0, 0).
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
    out.put_u8(0); // flags bitfield = "all absolute"
    VarInt(0).encode(&mut out).unwrap(); // teleport_id
    ConversionResult::Converted(vec![build_payload(V165_S2C_PLAYER_POS_LOOK, &out)])
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

    let x_fixed = body.get_i32();
    let y_fixed = body.get_i32();
    let z_fixed = body.get_i32();
    let yaw = body.get_i8();
    let pitch = body.get_i8();
    let _current_item = body.get_i16();

    // 1.6.4 fixed-point (1/32) → absolute double
    let x = x_fixed as f64 / 32.0;
    let y = y_fixed as f64 / 32.0;
    let z = z_fixed as f64 / 32.0;

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

    // 1.16.5 SpawnPlayer has no currentItem or trailing metadata byte.
    // Metadata begins with a proper DataWatcher terminator (0xFF) but
    // we emit the terminator byte directly as 1.16.5 expects metadata entries.
    out.put_u8(0xFF);

    ConversionResult::Converted(vec![build_payload(V165_S2C_SPAWN_PLAYER, &out)])
}

fn s2c_entity_teleport(mut body: Bytes) -> ConversionResult {
    // 1.6.4: i32 entity_id, i32 x (fixed-point 1/32), i32 y, i32 z, i8 yaw, i8 pitch
    // 1.16.5: VarInt entity_id, f64 x, f64 y, f64 z, u8 yaw, u8 pitch, bool on_ground
    if body.remaining() < 18 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body.get_i32();
    let x_fixed = body.get_i32();
    let y_fixed = body.get_i32();
    let z_fixed = body.get_i32();
    let yaw = body.get_i8();
    let pitch = body.get_i8();

    let x = x_fixed as f64 / 32.0;
    let y = y_fixed as f64 / 32.0;
    let z = z_fixed as f64 / 32.0;

    let mut out = BytesMut::with_capacity(18);
    VarInt(entity_id).encode(&mut out).unwrap();
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_u8(yaw as u8);
    out.put_u8(pitch as u8);
    out.put_u8(0);
    ConversionResult::Converted(vec![build_payload(V165_S2C_ENTITY_TELEPORT, &out)])
}

fn s2c_entity_rel_move(mut body: Bytes) -> ConversionResult {
    // 1.6.4: i32 entity_id, i8 dx/dy/dz (units of 1/32 block)
    // 1.16.5: VarInt entity_id, i16 dx/dy/dz (units of 1/4096 block), bool on_ground
    // 1/32 to 1/4096 = multiply by 128
    if body.remaining() < 7 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body.get_i32();
    let dx = body.get_i8();
    let dy = body.get_i8();
    let dz = body.get_i8();

    let dx_16 = (dx as i16 * 128).clamp(i16::MIN, i16::MAX);
    let dy_16 = (dy as i16 * 128).clamp(i16::MIN, i16::MAX);
    let dz_16 = (dz as i16 * 128).clamp(i16::MIN, i16::MAX);

    let mut out = BytesMut::with_capacity(8);
    VarInt(entity_id).encode(&mut out).unwrap();
    out.put_i16(dx_16);
    out.put_i16(dy_16);
    out.put_i16(dz_16);
    out.put_u8(0);
    ConversionResult::Converted(vec![build_payload(V165_S2C_ENTITY_REL_MOVE, &out)])
}

fn s2c_entity(mut body: Bytes) -> ConversionResult {
    // 1.6.4 SpawnObject: i32 entity_id, i8 entity_type, i32 x/y/z (fixed-point 1/32),
    //   i8 yaw/pitch/head_pitch, i16 velocity_x/y/z
    // 1.16.5 SpawnEntity: VarInt entity_id, UUID, VarInt entity_type, f64 x/y/z,
    //   u8 yaw/pitch/head_pitch, i16 velocity_x/y/z
    if body.remaining() < 4 + 1 + 12 + 3 + 6 {
        return ConversionResult::Passthrough;
    }

    let entity_id = body.get_i32();
    let _entity_type_raw = body.get_i8();
    let x_fixed = body.get_i32();
    let y_fixed = body.get_i32();
    let z_fixed = body.get_i32();
    let yaw = body.get_i8();
    let pitch = body.get_i8();
    let head_pitch = body.get_i8();
    let velocity_x = body.get_i16();
    let velocity_y = body.get_i16();
    let velocity_z = body.get_i16();

    let x = x_fixed as f64 / 32.0;
    let y = y_fixed as f64 / 32.0;
    let z = z_fixed as f64 / 32.0;

    let entity_uuid = uuid::Uuid::new_v4();
    // Entity type is NOT directly mappable between 1.6.4 and 1.16.5 registries.
    // Best-effort: pass the raw value as VarInt. Some entities will be wrong
    // but dropping the packet entirely is worse (no objects spawn at all).
    let entity_type = _entity_type_raw as i32;

    let mut out = BytesMut::new();
    VarInt(entity_id).encode(&mut out).unwrap();
    let (hi, lo) = entity_uuid.as_u64_pair();
    out.put_i64(hi as i64);
    out.put_i64(lo as i64);
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

    ConversionResult::Converted(vec![build_payload(V165_S2C_ENTITY, &out)])
}

fn s2c_block_change(mut body: Bytes) -> ConversionResult {
    // 1.6.4: i32 x, i8 y, i32 z, i32 block_id, i8 metadata
    // 1.16.5: i64 packed Position (1.14 layout), VarInt flattened block state
    if body.remaining() < 11 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32();
    let y = body.get_i8() as i32;
    let z = body.get_i32();
    let block_id = body.get_i32() as u32;
    let metadata = body.get_i8() as u32;

    let legacy_state = (block_id << 4) | (metadata & 0xF);
    let flattening = BlockFlatteningTable::new();
    let modern_state = match flattening.legacy_to_modern(legacy_state) {
        Some(s) => s,
        None => {
            tracing::warn!(
                legacy_state,
                "v1_6_4_to_v1_16_5: No mapping for legacy block state, dropping BlockChange"
            );
            return ConversionResult::Drop;
        },
    };

    let pos = kojacoord_protocol::types::Position { x, y, z };
    let packed = encode_modern_position(pos);

    let mut out = BytesMut::with_capacity(12);
    out.put_i64(packed);
    VarInt(modern_state as i32).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V165_S2C_BLOCK_CHANGE, &out)])
}

fn s2c_set_slot(body: Bytes) -> ConversionResult {
    // Convert SetSlot from 1.6.4 (legacy slot) to 1.16.5 (modern slot)
    let mut body_mut = BytesMut::from(body.as_ref());
    match items::convert_set_slot_legacy_to_modern(&mut body_mut) {
        Ok(()) => rebuild_with_id(V165_S2C_SET_SLOT, &body_mut.freeze()),
        Err(e) => {
            tracing::warn!(error = %e, "v1_6_4_to_v1_16_5: SetSlot conversion failed, dropping packet");
            ConversionResult::Drop
        },
    }
}

fn decode_varint_from(buf: &mut BytesMut) -> i32 {
    let mut tmp = buf.clone().freeze();
    let before = tmp.remaining();
    let val = VarInt::decode(&mut tmp).map(|v| v.0).unwrap_or(0);
    let consumed = before - tmp.remaining();
    buf.advance(consumed);
    val
}

fn s2c_window_items(body: Bytes) -> ConversionResult {
    let mut body_mut = BytesMut::from(body.as_ref());
    if body_mut.remaining() < 1 + 2 {
        return ConversionResult::Passthrough;
    }

    let window_id = body_mut.get_u8();
    let count = body_mut.get_i16();

    let mut modern_slots = Vec::new();
    for _ in 0..count {
        let has_item = body_mut.get_u8() != 0;
        let legacy_slot = if has_item {
            let item_id = body_mut.get_i16();
            let slot_count = body_mut.get_u8();
            let damage = body_mut.get_i16();
            let nbt_len = decode_varint_from(&mut body_mut);
            let nbt = if nbt_len > 0 {
                let nbt_bytes = body_mut.split_to(nbt_len as usize).to_vec();
                Some(
                    kojacoord_protocol::types::Nbt::decode(&mut bytes::Bytes::copy_from_slice(
                        &nbt_bytes,
                    ))
                    .unwrap_or_else(|_| kojacoord_protocol::types::Nbt::empty("")),
                )
            } else {
                None
            };
            items::LegacySlot(Some(items::LegacySlotData {
                item_id,
                count: slot_count as i8,
                damage,
                nbt,
            }))
        } else {
            items::LegacySlot(None)
        };

        modern_slots.push(items::legacy_slot_to_modern(&legacy_slot));
    }

    let mut out = BytesMut::new();
    out.put_u8(window_id);
    for slot in modern_slots {
        slot.encode(&mut out)
            .map_err(|e| format!("encode slot: {}", e))
            .unwrap();
    }

    rebuild_with_id(V165_S2C_WINDOW_ITEMS, &out.freeze())
}

fn s2c_entity_equipment(body: Bytes) -> ConversionResult {
    // Convert EntityEquipment from 1.6.4 (legacy slot) to 1.16.5 (modern slot)
    let mut body_mut = BytesMut::from(body.as_ref());
    if body_mut.remaining() < 6 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body_mut.get_i32();
    let slot = body_mut.get_i16();

    // Read legacy slot
    let has_item = body_mut.get_u8() != 0;
    let legacy_slot = if has_item {
        let item_id = body_mut.get_i16();
        let count = body_mut.get_u8();
        let damage = body_mut.get_i16();
        let nbt_len = decode_varint_from(&mut body_mut);
        let nbt = if nbt_len > 0 {
            let nbt_bytes = body_mut.split_to(nbt_len as usize).to_vec();
            Some(
                kojacoord_protocol::types::Nbt::decode(&mut bytes::Bytes::copy_from_slice(
                    &nbt_bytes,
                ))
                .unwrap_or_else(|_| kojacoord_protocol::types::Nbt::empty("")),
            )
        } else {
            None
        };
        items::LegacySlot(Some(items::LegacySlotData {
            item_id,
            count: count as i8,
            damage,
            nbt,
        }))
    } else {
        items::LegacySlot(None)
    };

    // Map legacy equipment slot to modern slot index
    let modern_slot_idx = match items::map_legacy_equipment_slot(slot) {
        Some(idx) => idx,
        None => {
            tracing::warn!(
                legacy_slot = slot,
                "v1_6_4_to_v1_16_5: No mapping for legacy equipment slot, dropping packet"
            );
            return ConversionResult::Drop;
        },
    };

    // Convert to modern slot
    let modern_slot = items::legacy_slot_to_modern(&legacy_slot);

    // Rebuild in modern format
    let mut out = BytesMut::new();
    VarInt(entity_id).encode(&mut out).unwrap();
    VarInt(modern_slot_idx as i32).encode(&mut out).unwrap();
    modern_slot
        .encode(&mut out)
        .map_err(|e| format!("encode slot: {}", e))
        .unwrap();

    rebuild_with_id(V165_S2C_ENTITY_EQUIPMENT, &out.freeze())
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
    ConversionResult::Converted(vec![build_payload(V165_S2C_EXPERIENCE, &out)])
}

fn s2c_held_item_change(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let slot = body.get_i8();

    let mut out = BytesMut::with_capacity(2);
    VarInt(slot as i32).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V165_S2C_HELD_ITEM_CHANGE, &out)])
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
    ConversionResult::Converted(vec![build_payload(V165_S2C_PLAYER_ABILITIES, &out)])
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

    ConversionResult::Converted(vec![build_payload(V165_S2C_DISCONNECT, &out)])
}

// Per the Notchian 1.6.4 pre-netty C2S packet table verified against
// HexaCord (`Packet0KeepAlive`, `Packet3Chat`) and MCP-doc convention
// `Packet<N><Name>` where decimal N = hex id.
// Previous values 0x01 (CHAT) and 0x05 (PLAYER_POS_LOOK) decoded to
// `Packet1Login` and `Packet5EntityEquipment` — entirely different
// packets. The converter silently passed 1.6.4 chat and movement c2s
// through unconverted, and the 1.16.5 backend dropped them as
// malformed.
const V164_C2S_KEEP_ALIVE: u8 = 0x00; // Packet0KeepAlive
const V164_C2S_CHAT: u8 = 0x03; // Packet3Chat (was 0x01)
const V164_C2S_USE_ENTITY: u8 = 0x07; // Packet7UseEntity
const V164_C2S_PLAYER_ON_GROUND: u8 = 0x0A; // Packet10Flying
const V164_C2S_MOVE_PLAYER_POS: u8 = 0x0B; // Packet11PlayerPosition
const V164_C2S_MOVE_PLAYER_ROT: u8 = 0x0C; // Packet12PlayerLook
const V164_C2S_PLAYER_POS_LOOK: u8 = 0x0D; // Packet13PlayerLookMove (was 0x05)
const V164_C2S_PLAYER_DIGGING: u8 = 0x0E; // Packet14BlockDig
const V164_C2S_PLAYER_BLOCK_PLACEMENT: u8 = 0x0F; // Packet15Place
const V164_C2S_HELD_ITEM_CHANGE: u8 = 0x10; // Packet16BlockItemSwitch
const V164_C2S_ANIMATION: u8 = 0x12; // Packet18Animation
const V164_C2S_ENTITY_ACTION: u8 = 0x13; // Packet19EntityAction
const V164_C2S_CLIENT_COMMAND: u8 = 0x16; // Packet22ClientCommand
const V164_C2S_CLOSE_WINDOW: u8 = 0x65; // Packet101CloseWindow
const V164_C2S_UPDATE_SIGN: u8 = 0x82; // Packet130UpdateSign
const V164_C2S_PLAYER_ABILITIES: u8 = 0xCA; // PacketCAPlayerAbilities
const V164_C2S_CLIENT_SETTINGS: u8 = 0xCC; // PacketCCSettings
const V164_C2S_PLUGIN_MESSAGE: u8 = 0xFA; // PacketFAPluginMessage

// Per `v1_16_5_to_v1_12_2.rs` sibling table + BungeeCord `Protocol.java::
// TO_SERVER` mappings for `MINECRAFT_1_16_2` (proto 751+ which 754 inherits).
// PLAYER_POS_LOOK was previously `0x11` — registry shows 0x14 is the actual
// MovePlayerPosRot id. Fixed below in the new constants block.
/// 1.16.5 c2s TeleportConfirm id. Pre-netty 1.6.4 had no concept of
/// teleport-acks so the converter doesn't synthesise these — kept as
/// documentation of the proto-754 table.
#[allow(dead_code)]
const V165_C2S_TELEPORT_CONFIRM: u8 = 0x00;
const V165_C2S_KEEP_ALIVE: u8 = 0x10;
const V165_C2S_CHAT: u8 = 0x03;
const V165_C2S_PLAYER_POS_LOOK: u8 = 0x14; // MovePlayerPosRot (was 0x11)
const V165_C2S_MOVE_PLAYER_POS: u8 = 0x12;
const V165_C2S_MOVE_PLAYER_ROT: u8 = 0x13;
const V165_C2S_PLAYER_DIGGING: u8 = 0x1B;
const V165_C2S_PLAYER_BLOCK_PLACEMENT: u8 = 0x2E;
const V165_C2S_HELD_ITEM_CHANGE: u8 = 0x25;
const V165_C2S_ENTITY_ACTION: u8 = 0x1C;
const V165_C2S_CLIENT_SETTINGS: u8 = 0x05;
const V165_C2S_CLIENT_STATUS: u8 = 0x04;
const V165_C2S_PLUGIN_MESSAGE: u8 = 0x0B;
const V165_C2S_ANIMATION: u8 = 0x2C;
const V165_C2S_PLAYER_ABILITIES: u8 = 0x19;
const V165_C2S_USE_ENTITY: u8 = 0x0E;
const V165_C2S_CLOSE_WINDOW: u8 = 0x0A;
const V165_C2S_UPDATE_SIGN: u8 = 0x2B;

pub fn convert_c2s(payload: Bytes) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    match id {
        V164_C2S_KEEP_ALIVE => c2s_keep_alive(body),
        V164_C2S_CHAT => c2s_chat(body),
        V164_C2S_USE_ENTITY => c2s_use_entity(body),
        V164_C2S_PLAYER_ON_GROUND => ConversionResult::Drop,
        V164_C2S_MOVE_PLAYER_POS => c2s_move_player_pos(body),
        V164_C2S_MOVE_PLAYER_ROT => c2s_move_player_rot(body),
        V164_C2S_PLAYER_POS_LOOK => c2s_player_pos_look(body),
        V164_C2S_PLAYER_DIGGING => c2s_player_digging(body),
        V164_C2S_PLAYER_BLOCK_PLACEMENT => c2s_player_block_placement(body),
        V164_C2S_HELD_ITEM_CHANGE => c2s_held_item_change(body),
        V164_C2S_ANIMATION => c2s_animation(body),
        V164_C2S_ENTITY_ACTION => c2s_entity_action(body),
        V164_C2S_CLIENT_COMMAND => c2s_client_command(body),
        V164_C2S_CLOSE_WINDOW => c2s_close_window(body),
        V164_C2S_UPDATE_SIGN => c2s_update_sign(body),
        V164_C2S_PLAYER_ABILITIES => c2s_player_abilities(body),
        V164_C2S_CLIENT_SETTINGS => c2s_client_settings(body),
        V164_C2S_PLUGIN_MESSAGE => c2s_plugin_message(body),
        _ => ConversionResult::Passthrough,
    }
}

fn c2s_keep_alive(mut body: Bytes) -> ConversionResult {
    // 1.6.4: i32 id. 1.16.5: i64 id.
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let id = body.get_i32();
    let mut out = BytesMut::with_capacity(8);
    out.put_i64(id as i64);
    ConversionResult::Converted(vec![build_payload(V165_C2S_KEEP_ALIVE, &out)])
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

    ConversionResult::Converted(vec![build_payload(V165_C2S_CHAT, &out)])
}

fn c2s_player_pos_look(mut body: Bytes) -> ConversionResult {
    // Same triple bug as the v1_6_4 → v1_12_2 sibling: 1.6.4 wire is
    // 4×f64 + 2×f32 + bool = 41 bytes; field order is X/Stance/Y/Z per
    // MCP `Packet13PlayerLookMove` constructor (verified against
    // HexaCord). Previous code read i32 in X/Y/Stance/Z order with a
    // 33-byte minimum check — every coord arrived garbage-cast and
    // Y/Stance were swapped.
    if body.remaining() < 41 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_f64();
    let _stance = body.get_f64();
    let y = body.get_f64();
    let z = body.get_f64();
    let yaw = body.get_f32();
    let pitch = body.get_f32();
    let on_ground = body.get_u8() != 0;

    let mut out = BytesMut::with_capacity(33);
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_f32(yaw);
    out.put_f32(pitch);
    out.put_u8(if on_ground { 1 } else { 0 });
    ConversionResult::Converted(vec![build_payload(V165_C2S_PLAYER_POS_LOOK, &out)])
}

fn c2s_player_digging(mut body: Bytes) -> ConversionResult {
    // 1.6.4: i8 status, i32 x, i8 y, i32 z, i8 face
    // 1.16.5: VarInt status, Position (1.14 packed i64), VarInt face
    if body.remaining() < 11 {
        return ConversionResult::Passthrough;
    }
    let status = body.get_i8();
    let x = body.get_i32();
    let y = body.get_i8() as i32;
    let z = body.get_i32();
    let face = body.get_i8();

    let pos = kojacoord_protocol::types::Position { x, y, z };
    let packed = encode_modern_position(pos);

    let mut out = BytesMut::new();
    VarInt(status as i32).encode(&mut out).unwrap();
    out.put_i64(packed);
    VarInt(face as i32).encode(&mut out).unwrap();

    ConversionResult::Converted(vec![build_payload(V165_C2S_PLAYER_DIGGING, &out)])
}

fn c2s_player_block_placement(mut body: Bytes) -> ConversionResult {
    // 1.6.4: i32 x, i8 y, i32 z, i8 direction, i16 held_item, i8 cx/cy/cz
    // 1.16.5: VarInt hand, Position (1.14 packed), VarInt face, f32 cx/cy/cz, bool inside_block
    if body.remaining() < 10 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32();
    let y = body.get_i8() as i32;
    let z = body.get_i32();
    let direction = body.get_i8();
    let _held_item = body.get_i16();
    let cx = body.get_i8();
    let cy = body.get_i8();
    let cz = body.get_i8();

    let pos = kojacoord_protocol::types::Position { x, y, z };
    let packed = encode_modern_position(pos);

    let mut out = BytesMut::new();
    VarInt(0).encode(&mut out).unwrap(); // hand = main_hand
    out.put_i64(packed);
    VarInt(direction as i32).encode(&mut out).unwrap();
    out.put_f32(cx as f32 / 16.0);
    out.put_f32(cy as f32 / 16.0);
    out.put_f32(cz as f32 / 16.0);
    out.put_u8(0); // inside_block = false

    ConversionResult::Converted(vec![build_payload(V165_C2S_PLAYER_BLOCK_PLACEMENT, &out)])
}

fn c2s_held_item_change(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let slot = body.get_i16();

    let mut out = BytesMut::with_capacity(2);
    VarInt(slot as i32).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V165_C2S_HELD_ITEM_CHANGE, &out)])
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

    ConversionResult::Converted(vec![build_payload(V165_C2S_ENTITY_ACTION, &out)])
}

// ── New batch: cover the c2s packets a real 1.6.4 client emits during
// steady-state gameplay against a 1.16.5 backend. Field shapes verified
// against KettleCord (1.6.x) + BungeeCord (1.16+) packet classes.

/// 1.6.4 Packet11PlayerPosition: f64 x, f64 y, f64 stance, f64 z, bool
/// on_ground. 1.16.5 MovePlayerPos: 3xf64 + bool on_ground.
fn c2s_move_player_pos(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 33 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_f64();
    let y = body.get_f64();
    let _stance = body.get_f64();
    let z = body.get_f64();
    let on_ground = body.get_u8() != 0;
    let mut out = BytesMut::new();
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_u8(if on_ground { 1 } else { 0 });
    ConversionResult::Converted(vec![build_payload(V165_C2S_MOVE_PLAYER_POS, &out)])
}

/// 1.6.4 Packet12PlayerLook: f32 yaw, f32 pitch, bool on_ground.
/// 1.16.5 MovePlayerRot: same shape.
fn c2s_move_player_rot(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 9 {
        return ConversionResult::Passthrough;
    }
    let yaw = body.get_f32();
    let pitch = body.get_f32();
    let on_ground = body.get_u8() != 0;
    let mut out = BytesMut::with_capacity(9);
    out.put_f32(yaw);
    out.put_f32(pitch);
    out.put_u8(if on_ground { 1 } else { 0 });
    ConversionResult::Converted(vec![build_payload(V165_C2S_MOVE_PLAYER_ROT, &out)])
}

/// 1.6.4 Packet7UseEntity: i32 user, i32 target, bool leftClick.
/// 1.16.5 Interact: VarInt target, VarInt type (0=interact, 1=attack),
/// bool sneaking.
fn c2s_use_entity(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 9 {
        return ConversionResult::Passthrough;
    }
    let _user = body.get_i32();
    let target = body.get_i32();
    let left_click = body.get_u8() != 0;
    let mut out = BytesMut::new();
    VarInt(target).encode(&mut out).unwrap();
    VarInt(if left_click { 1 } else { 0 })
        .encode(&mut out)
        .unwrap();
    out.put_u8(0);
    ConversionResult::Converted(vec![build_payload(V165_C2S_USE_ENTITY, &out)])
}

/// 1.6.4 Packet18Animation: i32 entity_id, i8 animation.
/// 1.16.5 Animation: VarInt hand.
fn c2s_animation(_body: Bytes) -> ConversionResult {
    let mut out = BytesMut::new();
    VarInt(0).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V165_C2S_ANIMATION, &out)])
}

/// 1.6.4 Packet22ClientCommand: i8 payload. 1.16.5 ClientStatus: VarInt action.
fn c2s_client_command(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let action = body.get_i8() as i32;
    let mut out = BytesMut::new();
    VarInt(action).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V165_C2S_CLIENT_STATUS, &out)])
}

/// 1.6.4 Packet101CloseWindow: u8 window_id. 1.16.5: same.
fn c2s_close_window(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let wid = body.get_u8();
    let mut out = BytesMut::with_capacity(1);
    out.put_u8(wid);
    ConversionResult::Converted(vec![build_payload(V165_C2S_CLOSE_WINDOW, &out)])
}

/// 1.6.4 Packet130UpdateSign: i32 x, i16 y, i32 z, 4 UCS-2 BE lines.
/// 1.16.5 UpdateSign: packed Position + 4 VarInt-string lines.
fn c2s_update_sign(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 2 + 4 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32();
    let y = body.get_i16() as i32;
    let z = body.get_i32();
    let pos = kojacoord_protocol::types::Position { x, y, z };
    let packed = kojacoord_protocol::types::encode_legacy_position(pos);

    let mut lines: [String; 4] = [String::new(), String::new(), String::new(), String::new()];
    for line in lines.iter_mut() {
        if body.remaining() < 2 {
            break;
        }
        let n = body.get_u16() as usize;
        if body.remaining() < n * 2 {
            break;
        }
        let mut u16s = Vec::with_capacity(n);
        for _ in 0..n {
            u16s.push(body.get_u16());
        }
        *line = String::from_utf16_lossy(&u16s);
    }

    let mut out = BytesMut::new();
    out.put_i64(packed);
    for line in &lines {
        VarInt(line.len() as i32).encode(&mut out).unwrap();
        out.extend_from_slice(line.as_bytes());
    }
    ConversionResult::Converted(vec![build_payload(V165_C2S_UPDATE_SIGN, &out)])
}

/// 1.6.4 PacketCAPlayerAbilities: i8 flags, f32 fly_speed, f32 walk_speed.
/// 1.16.5 PlayerAbilities: i8 flags only (1.16 dropped the speeds).
fn c2s_player_abilities(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 9 {
        return ConversionResult::Passthrough;
    }
    let flags = body.get_i8();
    let _ = body.get_f32();
    let _ = body.get_f32();
    let mut out = BytesMut::with_capacity(1);
    out.put_i8(flags);
    ConversionResult::Converted(vec![build_payload(V165_C2S_PLAYER_ABILITIES, &out)])
}

/// 1.6.4 PacketCCSettings: UCS-2 BE locale, i8 view_distance, i8 chat_flags,
/// i8 difficulty, bool show_cape.
/// 1.16.5 ClientSettings: String locale, i8 view_distance, VarInt chat_mode,
/// bool chat_colors, u8 displayed_skin_parts, VarInt main_hand.
fn c2s_client_settings(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let n = body.get_u16() as usize;
    if body.remaining() < n * 2 {
        return ConversionResult::Passthrough;
    }
    let mut u16s = Vec::with_capacity(n);
    for _ in 0..n {
        u16s.push(body.get_u16());
    }
    let locale = String::from_utf16_lossy(&u16s);
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let view_distance = body.get_i8();
    let chat_flags = body.get_i8();
    let _difficulty = body.get_i8();
    let _show_cape = body.get_u8();

    let mut out = BytesMut::new();
    VarInt(locale.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(locale.as_bytes());
    out.put_i8(view_distance);
    VarInt((chat_flags & 0x03) as i32).encode(&mut out).unwrap();
    out.put_u8(1);
    out.put_u8(0x7F);
    VarInt(1).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V165_C2S_CLIENT_SETTINGS, &out)])
}

/// 1.6.4 PacketFAPluginMessage: UCS-2 BE channel + u16 BE length + bytes.
/// 1.16.5 PluginMessage: String channel + raw bytes.
fn c2s_plugin_message(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let n = body.get_u16() as usize;
    if body.remaining() < n * 2 {
        return ConversionResult::Passthrough;
    }
    let mut u16s = Vec::with_capacity(n);
    for _ in 0..n {
        u16s.push(body.get_u16());
    }
    let channel = String::from_utf16_lossy(&u16s);
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
    ConversionResult::Converted(vec![build_payload(V165_C2S_PLUGIN_MESSAGE, &out)])
}
