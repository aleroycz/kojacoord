//! 1.16.5 → 1.12.2 packet converter — the inverse of [`super::v1_12_2_to_v1_16_5`].
//!
//! Crosses the 1.13 flattening boundary in the *down* direction. Everything
//! that carries flattened block-state IDs, item-state IDs, or palette chunk
//! data is dropped with a warn-trace (the proxy stays stable, the legacy
//! client just doesn't see those updates). Position bit layout is repacked
//! from the 1.14+ scheme back to the pre-1.14 scheme.
//!
//! Chunk data packets are handled by the chunk repacker for proper
//! cross-version conversion from Flattened (1.16.5) to Legacy (1.12.2).
//!
//! Reference: see the docstring on [`super::v1_12_2_to_v1_16_5`].

use bytes::{Buf, BufMut, Bytes, BytesMut};
use kojacoord_protocol::codec::{Decode, Encode};
use kojacoord_protocol::types::{Position, VarInt};
use kojacoord_protocol::{decode_modern_position, encode_legacy_position, BlockFlatteningTable};

use super::helpers::rebuild_with_id;
use super::items;
use super::{build_payload, split_id};
use crate::converter::ConversionResult;
use kojacoord_protocol::types::slot::Slot;

// ── S2C IDs (mirrored from the forward converter) ────────────────────────────
const V16_S2C_KEEP_ALIVE: u8 = 0x1F;
const V16_S2C_JOIN_GAME: u8 = 0x24;
const V16_S2C_CHAT: u8 = 0x0E;
const V16_S2C_PLAYER_POS_LOOK: u8 = 0x34;
const V16_S2C_SPAWN_POSITION: u8 = 0x42;
const V16_S2C_RESPAWN: u8 = 0x39;
const V16_S2C_DISCONNECT: u8 = 0x19;
const V16_S2C_HELD_ITEM_CHANGE: u8 = 0x3F;
// Per `crates/protocol/src/registry.rs` proto-754 table (verified
// against BungeeCord for the KeepAlive line). The previous 0x2F value
// here did not match the codebase's own registry and was inconsistent
// with the forward converter `v1_12_2_to_v1_16_5` which uses 0x30.
const V16_S2C_PLAYER_ABILITIES: u8 = 0x30;
const V16_S2C_SET_EXPERIENCE: u8 = 0x48;
const V16_S2C_BLOCK_CHANGE: u8 = 0x0B;
const V16_S2C_MULTI_BLOCK_CHANGE: u8 = 0x0F;
const V16_S2C_SET_SLOT: u8 = 0x15;
const V16_S2C_WINDOW_ITEMS: u8 = 0x13;
const V16_S2C_ENTITY_EQUIPMENT: u8 = 0x47;
const V16_S2C_CHUNK_DATA: u8 = 0x20;
const V16_S2C_ENTITY_TELEPORT: u8 = 0x56;
const V16_S2C_MOVE_ENTITY_POS: u8 = 0x28;
const V16_S2C_MOVE_ENTITY_POS_ROT: u8 = 0x29;
const V16_S2C_MOVE_ENTITY_ROT: u8 = 0x2A;
const V16_S2C_DESTROY_ENTITIES: u8 = 0x37;
const V16_S2C_ENTITY_HEAD_LOOK: u8 = 0x3B;
const V16_S2C_ENTITY_VELOCITY: u8 = 0x46;

const V12_S2C_KEEP_ALIVE: u8 = 0x1F;
const V12_S2C_JOIN_GAME: u8 = 0x23;
const V12_S2C_CHAT: u8 = 0x0F;
const V12_S2C_PLAYER_POS_LOOK: u8 = 0x2F;
const V12_S2C_SPAWN_POSITION: u8 = 0x46;
const V12_S2C_RESPAWN: u8 = 0x35;
const V12_S2C_DISCONNECT: u8 = 0x1A;
const V12_S2C_HELD_ITEM_CHANGE: u8 = 0x3A;
const V12_S2C_PLAYER_ABILITIES: u8 = 0x2C;
const V12_S2C_SET_EXPERIENCE: u8 = 0x40;
const V12_S2C_ENTITY_TELEPORT: u8 = 0x4C;
const V12_S2C_MOVE_ENTITY_POS: u8 = 0x26;
const V12_S2C_MOVE_ENTITY_POS_ROT: u8 = 0x27;
const V12_S2C_MOVE_ENTITY_ROT: u8 = 0x28;
const V12_S2C_DESTROY_ENTITIES: u8 = 0x32;
const V12_S2C_ENTITY_HEAD_LOOK: u8 = 0x36;
const V12_S2C_ENTITY_VELOCITY: u8 = 0x3E;
const V12_S2C_BLOCK_CHANGE: u8 = 0x0B;
const V12_S2C_MULTI_BLOCK_CHANGE: u8 = 0x10;
const V12_S2C_SET_SLOT: u8 = 0x16;
const V12_S2C_WINDOW_ITEMS: u8 = 0x14;
const V12_S2C_ENTITY_EQUIPMENT: u8 = 0x3F;
const V12_S2C_CHUNK_DATA: u8 = 0x20;

// ── C2S IDs ──────────────────────────────────────────────────────────────────
const V16_C2S_TELEPORT_CONFIRM: u8 = 0x00;
const V16_C2S_CHAT: u8 = 0x03;
const V16_C2S_CLIENT_STATUS: u8 = 0x04;
const V16_C2S_CLIENT_SETTINGS: u8 = 0x05;
const V16_C2S_PLUGIN_MESSAGE: u8 = 0x0B;
const V16_C2S_INTERACT: u8 = 0x0E;
const V16_C2S_KEEP_ALIVE: u8 = 0x10;
const V16_C2S_MOVE_PLAYER_POS: u8 = 0x12;
const V16_C2S_MOVE_PLAYER_ROT: u8 = 0x13;
const V16_C2S_MOVE_PLAYER_POS_ROT: u8 = 0x14;
const V16_C2S_PLAYER_ABILITIES: u8 = 0x19;
const V16_C2S_PLAYER_DIGGING: u8 = 0x1B;
const V16_C2S_ENTITY_ACTION: u8 = 0x1C;
const V16_C2S_HELD_ITEM_CHANGE: u8 = 0x25;
const V16_C2S_ANIMATION: u8 = 0x2C;
const V16_C2S_PLAYER_BLOCK_PLACEMENT: u8 = 0x2E;
const V16_C2S_USE_ITEM: u8 = 0x2F;

const V12_C2S_TELEPORT_CONFIRM: u8 = 0x00;
const V12_C2S_CHAT: u8 = 0x02;
const V12_C2S_CLIENT_STATUS: u8 = 0x03;
const V12_C2S_CLIENT_SETTINGS: u8 = 0x04;
const V12_C2S_PLUGIN_MESSAGE: u8 = 0x09;
const V12_C2S_INTERACT: u8 = 0x0A;
const V12_C2S_KEEP_ALIVE: u8 = 0x0B;
const V12_C2S_MOVE_PLAYER_POS: u8 = 0x0C;
const V12_C2S_MOVE_PLAYER_POS_ROT: u8 = 0x0D;
const V12_C2S_MOVE_PLAYER_ROT: u8 = 0x0E;
const V12_C2S_PLAYER_ABILITIES: u8 = 0x12;
const V12_C2S_PLAYER_DIGGING: u8 = 0x14;
const V12_C2S_ENTITY_ACTION: u8 = 0x15;
const V12_C2S_HELD_ITEM_CHANGE: u8 = 0x1A;
const V12_C2S_ANIMATION: u8 = 0x1D;
const V12_C2S_PLAYER_BLOCK_PLACEMENT: u8 = 0x1F;
const V12_C2S_USE_ITEM: u8 = 0x20;

// ── Position repacking (modern → legacy) ─────────────────────────────────────

// ── S2C dispatch ─────────────────────────────────────────────────────────────

pub fn convert_s2c(
    payload: Bytes,
    repacker: Option<std::sync::Arc<crate::converter::chunk_repack::ChunkRepacker>>,
) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    match id {
        V16_S2C_KEEP_ALIVE => rebuild_with_id(V12_S2C_KEEP_ALIVE, &body),
        V16_S2C_JOIN_GAME => s2c_join_game(body),
        V16_S2C_CHAT => s2c_chat(body),
        V16_S2C_PLAYER_POS_LOOK => rebuild_with_id(V12_S2C_PLAYER_POS_LOOK, &body),
        V16_S2C_SPAWN_POSITION => s2c_spawn_position(body),
        V16_S2C_RESPAWN => s2c_respawn(body),
        V16_S2C_DISCONNECT => rebuild_with_id(V12_S2C_DISCONNECT, &body),
        V16_S2C_HELD_ITEM_CHANGE => rebuild_with_id(V12_S2C_HELD_ITEM_CHANGE, &body),
        V16_S2C_PLAYER_ABILITIES => rebuild_with_id(V12_S2C_PLAYER_ABILITIES, &body),
        V16_S2C_SET_EXPERIENCE => rebuild_with_id(V12_S2C_SET_EXPERIENCE, &body),
        V16_S2C_ENTITY_TELEPORT => rebuild_with_id(V12_S2C_ENTITY_TELEPORT, &body),
        V16_S2C_MOVE_ENTITY_POS => rebuild_with_id(V12_S2C_MOVE_ENTITY_POS, &body),
        V16_S2C_MOVE_ENTITY_POS_ROT => rebuild_with_id(V12_S2C_MOVE_ENTITY_POS_ROT, &body),
        V16_S2C_MOVE_ENTITY_ROT => rebuild_with_id(V12_S2C_MOVE_ENTITY_ROT, &body),
        V16_S2C_DESTROY_ENTITIES => rebuild_with_id(V12_S2C_DESTROY_ENTITIES, &body),
        V16_S2C_ENTITY_HEAD_LOOK => rebuild_with_id(V12_S2C_ENTITY_HEAD_LOOK, &body),
        V16_S2C_ENTITY_VELOCITY => rebuild_with_id(V12_S2C_ENTITY_VELOCITY, &body),

        V16_S2C_BLOCK_CHANGE => {
            let mut cur = body;
            if cur.remaining() < 8 {
                return ConversionResult::Passthrough;
            }
            let packed_modern = cur.get_u64();
            let pos = decode_modern_position(packed_modern);
            let modern_state = match VarInt::decode(&mut cur) {
                Ok(v) => v.0 as u32,
                Err(_) => return ConversionResult::Passthrough,
            };

            // Map modern state to legacy state using flattening table
            let flattening = BlockFlatteningTable::new();
            let legacy_state = match flattening.modern_to_legacy(modern_state) {
                Some(state) => state,
                None => {
                    tracing::warn!(modern_state, "v1_16_5_to_v1_12_2: No mapping for modern block state, dropping BlockChange");
                    return ConversionResult::Drop;
                },
            };

            let packed_legacy = encode_legacy_position(pos);

            let mut out = BytesMut::new();
            out.put_u64(packed_legacy as u64);
            VarInt(legacy_state as i32).encode(&mut out).unwrap();

            rebuild_with_id(V12_S2C_BLOCK_CHANGE, &out.freeze())
        },
        V16_S2C_MULTI_BLOCK_CHANGE => {
            let mut cur = body;
            if cur.remaining() < 8 {
                return ConversionResult::Passthrough;
            }
            let chunk_x = cur.get_i32();
            let chunk_z = cur.get_i32();
            let count = VarInt::decode(&mut cur)
                .map_err(|e| format!("decode count: {}", e))
                .unwrap()
                .0 as usize;

            let flattening = BlockFlatteningTable::new();
            let mut out = BytesMut::new();
            out.put_i32(chunk_x);
            out.put_i32(chunk_z);
            VarInt(count as i32).encode(&mut out).unwrap();

            for _ in 0..count {
                let long_offset = VarInt::decode(&mut cur)
                    .map_err(|e| format!("decode offset: {}", e))
                    .unwrap()
                    .0 as u64;
                let state = VarInt::decode(&mut cur)
                    .map_err(|e| format!("decode state: {}", e))
                    .unwrap()
                    .0 as u32;

                // Convert long offset to x, y, z coordinates
                // 1.16.5 packs as: ((y & 0xF) << 8) | (z << 4) | x within a section
                let x = (long_offset & 0xF) as i16;
                let z = ((long_offset >> 4) & 0xF) as i16;
                let y = ((long_offset >> 8) & 0xF) as i16;

                // Map modern state to legacy state using flattening table
                let legacy_state = match flattening.modern_to_legacy(state) {
                    Some(s) => s,
                    None => {
                        tracing::warn!(state, "v1_16_5_to_v1_12_2: No mapping for modern block state in MultiBlockChange, skipping record");
                        continue;
                    },
                };

                let block_id = (legacy_state >> 4) as i32;
                let block_data = (legacy_state & 0xF) as i32;

                out.put_i16(x);
                out.put_i16(y);
                out.put_i16(z);
                VarInt(block_id).encode(&mut out).unwrap();
                VarInt(block_data).encode(&mut out).unwrap();
            }

            rebuild_with_id(V12_S2C_MULTI_BLOCK_CHANGE, &out.freeze())
        },
        V16_S2C_CHUNK_DATA => {
            // Use chunk repacker to convert from Flattened (1.16.5) to Legacy (1.12.2)
            if let Some(repacker) = repacker {
                match repacker.repack(
                    &body,
                    kojacoord_protocol::ProtocolVersion::V1_16_5,
                    kojacoord_protocol::ProtocolVersion::V1_12_2,
                ) {
                    Ok(converted_body) => {
                        tracing::debug!("v1_16_5_to_v1_12_2: Successfully repacked chunk data");
                        rebuild_with_id(
                            V12_S2C_CHUNK_DATA,
                            &bytes::Bytes::copy_from_slice(&converted_body),
                        )
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "v1_16_5_to_v1_12_2: Chunk repacking failed, dropping packet");
                        ConversionResult::Drop
                    },
                }
            } else {
                tracing::warn!(
                    "v1_16_5_to_v1_12_2: No chunk repacker available, dropping ChunkData"
                );
                ConversionResult::Drop
            }
        },
        V16_S2C_SET_SLOT => {
            let mut cur = body;
            if cur.remaining() < 1 + 2 {
                return ConversionResult::Passthrough;
            }
            let window_id = cur.get_u8();
            let slot_idx = cur.get_i16();
            let modern_slot = match Slot::decode(&mut cur) {
                Ok(s) => s,
                Err(_) => return ConversionResult::Passthrough,
            };
            let legacy_slot = items::modern_slot_to_legacy(&modern_slot);

            let mut out = BytesMut::new();
            out.put_u8(window_id);
            out.put_i16(slot_idx);
            match legacy_slot.0 {
                None => out.put_u8(0),
                Some(data) => {
                    out.put_u8(1);
                    out.put_i16(data.item_id);
                    out.put_u8(data.count as u8);
                    out.put_i16(data.damage);
                    match &data.nbt {
                        None => VarInt(0).encode(&mut out).unwrap(),
                        Some(nbt) => {
                            nbt.encode(&mut out).unwrap();
                        },
                    }
                },
            }
            rebuild_with_id(V12_S2C_SET_SLOT, &out.freeze())
        },
        V16_S2C_WINDOW_ITEMS => {
            let mut cur = body;
            let window_id = cur.get_u8();
            let count = VarInt::decode(&mut cur)
                .map_err(|e| format!("decode count: {}", e))
                .unwrap()
                .0 as usize;

            let mut legacy_slots = Vec::new();
            for _ in 0..count {
                let modern_slot = Slot::decode(&mut cur)
                    .map_err(|e| format!("decode slot: {}", e))
                    .unwrap();
                legacy_slots.push(items::modern_slot_to_legacy(&modern_slot));
            }

            // Rebuild in legacy format
            let mut out = BytesMut::new();
            out.put_u8(window_id);
            for slot in legacy_slots {
                match slot.0 {
                    None => out.put_u8(0),
                    Some(data) => {
                        out.put_u8(1);
                        out.put_i16(data.item_id);
                        out.put_u8(data.count as u8);
                        out.put_i16(data.damage);
                        match &data.nbt {
                            None => VarInt(0).encode(&mut out).unwrap(),
                            Some(nbt) => {
                                nbt.encode(&mut out).unwrap();
                            },
                        }
                    },
                }
            }

            rebuild_with_id(V12_S2C_WINDOW_ITEMS, &out.freeze())
        },
        V16_S2C_ENTITY_EQUIPMENT => {
            let mut cur = body;
            let entity_id = match VarInt::decode(&mut cur) {
                Ok(v) => v.0,
                Err(_) => return ConversionResult::Passthrough,
            };
            if cur.remaining() < 1 {
                return ConversionResult::Passthrough;
            }
            let slot = cur.get_u8();

            // Read modern slot
            let modern_slot = Slot::decode(&mut cur)
                .map_err(|e| format!("decode slot: {}", e))
                .unwrap();

            // Map modern slot to legacy slot
            let legacy_slot_idx = match items::map_equipment_slot(slot) {
                Some(idx) => idx,
                None => {
                    // Off-hand (slot 1) doesn't exist in legacy, drop this packet
                    tracing::trace!(slot, "v1_16_5_to_v1_12_2: Off-hand equipment not supported in legacy, dropping packet");
                    return ConversionResult::Drop;
                },
            };

            let legacy_slot = items::modern_slot_to_legacy(&modern_slot);

            let mut out = BytesMut::new();
            out.put_i32(entity_id);
            out.put_i16(legacy_slot_idx);
            match legacy_slot.0 {
                None => out.put_u8(0),
                Some(data) => {
                    out.put_u8(1);
                    out.put_i16(data.item_id);
                    out.put_u8(data.count as u8);
                    out.put_i16(data.damage);
                    match &data.nbt {
                        None => VarInt(0).encode(&mut out).unwrap(),
                        Some(nbt) => {
                            nbt.encode(&mut out).unwrap();
                        },
                    }
                },
            }

            rebuild_with_id(V12_S2C_ENTITY_EQUIPMENT, &out.freeze())
        },
        _ => ConversionResult::Passthrough,
    }
}

fn s2c_chat(mut body: Bytes) -> ConversionResult {
    // 1.16.5: <String json> <byte position> <UUID sender>. Strip the UUID.
    let str_len = match VarInt::decode(&mut body) {
        Ok(v) => v.0 as usize,
        Err(_) => return ConversionResult::Passthrough,
    };
    if body.remaining() < str_len + 1 + 16 {
        return ConversionResult::Passthrough;
    }
    let mut json = vec![0u8; str_len];
    body.copy_to_slice(&mut json);
    let position = body.get_u8();
    body.advance(16); // discard UUID

    let mut out = BytesMut::new();
    VarInt(str_len as i32).encode(&mut out).unwrap();
    out.extend_from_slice(&json);
    out.put_u8(position);
    ConversionResult::Converted(vec![build_payload(V12_S2C_CHAT, &out)])
}

fn s2c_spawn_position(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let pos = match Position::decode(&mut body) {
        Ok(p) => p,
        Err(_) => return ConversionResult::Passthrough,
    };
    let packed = encode_legacy_position(pos);
    let mut out = BytesMut::with_capacity(8);
    out.put_u64(packed as u64);
    ConversionResult::Converted(vec![build_payload(V12_S2C_SPAWN_POSITION, &out)])
}

fn s2c_join_game(mut body: Bytes) -> ConversionResult {
    // 1.16.5 wire shape per BungeeCord `Login.java::read` for proto 754
    // (`MINECRAFT_1_16_2`):
    //   i32 entityId, bool hardcore, u8 gameMode, i8 prevGameMode,
    //   VarInt n_worlds, n × String worldNames,
    //   NBT dimension_codec, NBT dimension,    ← previously missed
    //   String worldName, i64 hashedSeed, VarInt maxPlayers,
    //   VarInt viewDistance, bool reducedDebug, bool normalRespawn,
    //   bool debug, bool flat.
    //
    // The previous reader treated `dimension` as a length-prefixed String
    // and skipped the `dimension_codec` entirely — when a real 1.16.5
    // backend sent JoinGame, the parser ran straight into the codec NBT
    // bytes treating them as a VarInt world-count, producing garbage for
    // every following field. This converter then emitted a 1.12.2
    // JoinGame with wrong gamemode / dimension / level_type — the 1.12.2
    // client either disconnected or spawned in the wrong world.
    use kojacoord_protocol::types::nbt;
    if body.remaining() < 4 + 3 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body.get_i32();
    let _hardcore = body.get_u8();
    let gamemode = body.get_u8();
    let _prev_gm = body.get_i8();
    let n_worlds = match VarInt::decode(&mut body) {
        Ok(v) => v.0 as usize,
        Err(_) => return ConversionResult::Passthrough,
    };
    for _ in 0..n_worlds {
        if decode_string(&mut body).is_none() {
            return ConversionResult::Passthrough;
        }
    }
    // Skip dimension_codec NBT (self-framing). If the skip fails treat
    // as Passthrough so the upstream pipeline can decide.
    if nbt::skip(&mut body).is_err() {
        return ConversionResult::Passthrough;
    }
    // Skip dimension NBT (self-framing). Real 1.16.5 servers send this as
    // a `minecraft:dimension_type` element NBT. We don't need its
    // contents — we map by world_name below.
    if nbt::skip(&mut body).is_err() {
        return ConversionResult::Passthrough;
    }
    let world_name = match decode_string(&mut body) {
        Some(s) => s,
        None => return ConversionResult::Passthrough,
    };
    // Map 1.16.5 dimension to legacy int by world name. This is what the
    // 1.12.2 client expects in its dimension field.
    let dimension = world_name.clone();
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let _hashed_seed = body.get_i64();
    let _max_players = match VarInt::decode(&mut body) {
        Ok(v) => v.0,
        Err(_) => return ConversionResult::Passthrough,
    };
    let _view_distance = match VarInt::decode(&mut body) {
        Ok(v) => v.0,
        Err(_) => return ConversionResult::Passthrough,
    };
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let reduced_debug_info = body.get_u8() != 0;
    let _enable_respawn = body.get_u8();
    let _is_debug = body.get_u8();
    let is_flat = body.get_u8() != 0;

    let dim_i32 = dimension_key_to_i32(&dimension);

    let mut out = BytesMut::new();
    out.put_i32(entity_id);
    out.put_u8(gamemode & 0x07);
    out.put_i32(dim_i32);
    out.put_u8(0); // difficulty: peaceful (legacy default)
    out.put_u8(20); // max_players (ignored by client)
    let level = if is_flat { "flat" } else { "default" };
    let bytes = level.as_bytes();
    VarInt(bytes.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(bytes);
    out.put_u8(reduced_debug_info as u8);

    ConversionResult::Converted(vec![build_payload(V12_S2C_JOIN_GAME, &out)])
}

fn s2c_respawn(mut body: Bytes) -> ConversionResult {
    // Per BungeeCord `Respawn.java::read` for proto 754
    // (`MINECRAFT_1_16_2 <= proto < MINECRAFT_1_19`), the leading
    // `dimension` field is NBT, not String. Same shape bug as
    // `s2c_join_game` above — read NBT, then `worldName` String, then
    // the post-1.16 tail.
    use kojacoord_protocol::types::nbt;
    if nbt::skip(&mut body).is_err() {
        return ConversionResult::Passthrough;
    }
    let world_name = match decode_string(&mut body) {
        Some(s) => s,
        None => return ConversionResult::Passthrough,
    };
    if body.remaining() < 8 + 1 + 1 + 1 + 1 + 1 {
        return ConversionResult::Passthrough;
    }
    let _hashed_seed = body.get_i64();
    let game_mode = body.get_u8();
    let _prev_gm = body.get_i8();
    let _is_debug = body.get_u8();
    let is_flat = body.get_u8() != 0;
    let _copy_metadata = body.get_u8();

    let dim_i32 = dimension_key_to_i32(&world_name);

    let mut out = BytesMut::new();
    out.put_i32(dim_i32);
    out.put_u8(0); // difficulty: peaceful
    out.put_u8(game_mode & 0x07);
    let level = if is_flat { "flat" } else { "default" };
    let bytes = level.as_bytes();
    VarInt(bytes.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(bytes);
    ConversionResult::Converted(vec![build_payload(V12_S2C_RESPAWN, &out)])
}

fn dimension_key_to_i32(key: &str) -> i32 {
    match key {
        "minecraft:the_nether" => -1,
        "minecraft:the_end" => 1,
        _ => 0,
    }
}

// ── C2S dispatch ─────────────────────────────────────────────────────────────

pub fn convert_c2s(payload: Bytes) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    match id {
        V16_C2S_TELEPORT_CONFIRM => rebuild_with_id(V12_C2S_TELEPORT_CONFIRM, &body),
        V16_C2S_CHAT => rebuild_with_id(V12_C2S_CHAT, &body),
        V16_C2S_CLIENT_STATUS => rebuild_with_id(V12_C2S_CLIENT_STATUS, &body),
        V16_C2S_CLIENT_SETTINGS => rebuild_with_id(V12_C2S_CLIENT_SETTINGS, &body),
        V16_C2S_PLUGIN_MESSAGE => rebuild_with_id(V12_C2S_PLUGIN_MESSAGE, &body),
        V16_C2S_INTERACT => rebuild_with_id(V12_C2S_INTERACT, &body),
        V16_C2S_KEEP_ALIVE => rebuild_with_id(V12_C2S_KEEP_ALIVE, &body),
        V16_C2S_MOVE_PLAYER_POS => rebuild_with_id(V12_C2S_MOVE_PLAYER_POS, &body),
        V16_C2S_MOVE_PLAYER_POS_ROT => rebuild_with_id(V12_C2S_MOVE_PLAYER_POS_ROT, &body),
        V16_C2S_MOVE_PLAYER_ROT => rebuild_with_id(V12_C2S_MOVE_PLAYER_ROT, &body),
        V16_C2S_PLAYER_ABILITIES => rebuild_with_id(V12_C2S_PLAYER_ABILITIES, &body),
        V16_C2S_PLAYER_DIGGING => c2s_player_digging(body),
        V16_C2S_ENTITY_ACTION => rebuild_with_id(V12_C2S_ENTITY_ACTION, &body),
        V16_C2S_HELD_ITEM_CHANGE => rebuild_with_id(V12_C2S_HELD_ITEM_CHANGE, &body),
        V16_C2S_ANIMATION => rebuild_with_id(V12_C2S_ANIMATION, &body),
        V16_C2S_PLAYER_BLOCK_PLACEMENT => c2s_player_block_placement(body),
        V16_C2S_USE_ITEM => rebuild_with_id(V12_C2S_USE_ITEM, &body),
        _ => ConversionResult::Passthrough,
    }
}

fn c2s_player_digging(mut body: Bytes) -> ConversionResult {
    let status = match VarInt::decode(&mut body) {
        Ok(v) => v.0,
        Err(_) => return ConversionResult::Passthrough,
    };
    let pos = match Position::decode(&mut body) {
        Ok(p) => p,
        Err(_) => return ConversionResult::Passthrough,
    };
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let face = body.get_i8();

    let mut out = BytesMut::new();
    VarInt(status).encode(&mut out).unwrap();
    out.put_u64(encode_legacy_position(pos) as u64);
    out.put_i8(face);
    ConversionResult::Converted(vec![build_payload(V12_C2S_PLAYER_DIGGING, &out)])
}

fn c2s_player_block_placement(mut body: Bytes) -> ConversionResult {
    // 1.16.5: <VarInt hand> <Position> <VarInt face> <f32 cx> <f32 cy> <f32 cz> <bool inside_block>.
    // 1.12.2: <Position> <VarInt face> <VarInt hand> <f32 cx> <f32 cy> <f32 cz>.
    let hand = match VarInt::decode(&mut body) {
        Ok(v) => v.0,
        Err(_) => return ConversionResult::Passthrough,
    };
    let pos = match Position::decode(&mut body) {
        Ok(p) => p,
        Err(_) => return ConversionResult::Passthrough,
    };
    let face = match VarInt::decode(&mut body) {
        Ok(v) => v.0,
        Err(_) => return ConversionResult::Passthrough,
    };
    if body.remaining() < 12 + 1 {
        return ConversionResult::Passthrough;
    }
    let cx = body.get_f32();
    let cy = body.get_f32();
    let cz = body.get_f32();
    let _inside = body.get_u8();

    let mut out = BytesMut::new();
    out.put_u64(encode_legacy_position(pos) as u64);
    VarInt(face).encode(&mut out).unwrap();
    VarInt(hand).encode(&mut out).unwrap();
    out.put_f32(cx);
    out.put_f32(cy);
    out.put_f32(cz);
    ConversionResult::Converted(vec![build_payload(V12_C2S_PLAYER_BLOCK_PLACEMENT, &out)])
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn decode_string(body: &mut Bytes) -> Option<String> {
    let len = VarInt::decode(body).ok()?.0 as usize;
    if body.remaining() < len {
        return None;
    }
    let mut buf = vec![0u8; len];
    body.copy_to_slice(&mut buf);
    String::from_utf8(buf).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modern_position(p: Position) -> u64 {
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        b.get_u64()
    }

    #[test]
    fn legacy_position_roundtrip_via_re_encode() {
        for p in [
            Position::new(0, 0, 0),
            Position::new(100, 64, -200),
            Position::new(-33554432, 2047, 33554431),
        ] {
            let packed = encode_legacy_position(p);
            // Re-decode via the legacy decoder used in the forward converter.
            let v = packed as i64;
            let mut x = (v >> 38) & 0x3FF_FFFF;
            let mut y = (v >> 26) & 0xFFF;
            let mut z = v & 0x3FF_FFFF;
            if x >= 0x200_0000 {
                x -= 0x400_0000;
            }
            if z >= 0x200_0000 {
                z -= 0x400_0000;
            }
            if y >= 0x800 {
                y -= 0x1000;
            }
            assert_eq!(
                Position {
                    x: x as i32,
                    y: y as i32,
                    z: z as i32,
                },
                p,
                "legacy roundtrip"
            );
        }
    }

    #[test]
    fn join_game_strips_codec_and_translates_dimension() {
        // Construct a real 1.16.5 JoinGame body — per BungeeCord
        // `Login.java::read` for proto 754:
        //   i32 eid, bool hardcore, u8 gm, i8 prev_gm,
        //   VarInt n_worlds, n × String worldNames,
        //   NBT dimension_codec, NBT dimension,
        //   String worldName, i64 seed, VarInt maxPlayers,
        //   VarInt viewDistance, bool reducedDebug, bool normalRespawn,
        //   bool debug, bool flat.
        //
        // Minimal NBT (Java named-tag format): [0x0A (Compound)]
        //   [0x00 0x00 (empty name length u16)] [0x00 (TAG_End)] =
        // 4 bytes total. `nbt::skip` consumes the leading tag byte,
        // the empty name, then iterates compound children until the
        // closing TAG_End — perfect for an empty compound.
        const MINIMAL_NBT: &[u8] = &[0x0A, 0x00, 0x00, 0x00];

        let mut body = BytesMut::new();
        body.put_i32(7); // eid
        body.put_u8(0); // hardcore
        body.put_u8(2); // gm
        body.put_i8(-1); // prev_gm
        VarInt(1).encode(&mut body).unwrap(); // n_worlds
        let w = b"minecraft:the_nether";
        VarInt(w.len() as i32).encode(&mut body).unwrap();
        body.extend_from_slice(w);
        body.extend_from_slice(MINIMAL_NBT); // NBT dimension_codec
        body.extend_from_slice(MINIMAL_NBT); // NBT dimension
        VarInt(w.len() as i32).encode(&mut body).unwrap();
        body.extend_from_slice(w); // world name
        body.put_i64(0);
        VarInt(0).encode(&mut body).unwrap();
        VarInt(8).encode(&mut body).unwrap();
        body.put_u8(0);
        body.put_u8(1);
        body.put_u8(0);
        body.put_u8(0);

        let res = s2c_join_game(body.freeze());
        let pkts = match res {
            ConversionResult::Converted(v) => v,
            _ => panic!("expected Converted"),
        };
        let mut out = pkts[0].clone();
        let id = VarInt::decode(&mut out).unwrap().0 as u8;
        assert_eq!(id, V12_S2C_JOIN_GAME);
        let eid = out.get_i32();
        assert_eq!(eid, 7);
        let gm = out.get_u8();
        assert_eq!(gm, 2);
        let dim = out.get_i32();
        assert_eq!(dim, -1);
    }

    #[test]
    fn spawn_position_repacks_to_legacy_layout() {
        let pos = Position::new(10, 80, -30);
        let packed_modern = modern_position(pos);
        let mut body = BytesMut::new();
        body.put_u64(packed_modern);

        let res = s2c_spawn_position(body.freeze());
        let pkts = match res {
            ConversionResult::Converted(v) => v,
            _ => panic!("expected Converted"),
        };
        let mut out = pkts[0].clone();
        let id = VarInt::decode(&mut out).unwrap().0 as u8;
        assert_eq!(id, V12_S2C_SPAWN_POSITION);
        let packed = out.get_u64();
        // `encode_legacy_position` returns an i64 (the on-wire signed
        // representation); compare bit-patterns so we don't reject a
        // perfectly-fine round-trip because of sign-mismatched types.
        assert_eq!(packed, encode_legacy_position(pos) as u64);
    }

    #[test]
    fn chat_strips_sender_uuid() {
        let json = br#"{"text":"hi"}"#;
        let mut body = BytesMut::new();
        VarInt(json.len() as i32).encode(&mut body).unwrap();
        body.extend_from_slice(json);
        body.put_u8(0);
        body.put_u64(0);
        body.put_u64(0);

        let res = s2c_chat(body.freeze());
        let pkts = match res {
            ConversionResult::Converted(v) => v,
            _ => panic!("expected Converted"),
        };
        let mut out = pkts[0].clone();
        let id = VarInt::decode(&mut out).unwrap().0 as u8;
        assert_eq!(id, V12_S2C_CHAT);
        let len = VarInt::decode(&mut out).unwrap().0 as usize;
        assert_eq!(len, json.len());
        out.advance(len);
        let pos = out.get_u8();
        assert_eq!(pos, 0);
        assert_eq!(out.remaining(), 0);
    }
}
