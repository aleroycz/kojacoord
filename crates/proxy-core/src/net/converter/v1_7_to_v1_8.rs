#![allow(dead_code)]
//! 1.7.10 (protocol 5) ↔ 1.8.x (protocol 47) translation, server→client and
//! client→server.
//!
//! References used while writing this module (no live web access — drawn from
//! the canonical wire-format spec on minecraft.wiki / wiki.vg mirror and the
//! PrismarineJS minecraft-data 1.7 / 1.8 proto.yml files):
//!
//! Key wire-format differences from 1.7.10 → 1.8:
//! * Position encoding: 1.7 uses separate `i32 x, u8 y, i32 z`; 1.8 introduced
//!   the packed-long `Position` (26+12+26 bits).
//! * Chat (S2C): 1.8 added a trailing `position: byte` field (0 = chat,
//!   1 = system, 2 = above hotbar).
//! * Player Position And Look (S2C 0x08): 1.7 has 4 doubles (x, stance, y, z)
//!   plus yaw/pitch/on_ground; 1.8 drops `stance` (3 doubles) and replaces
//!   `on_ground` with a `flags` byte.
//! * Use Entity (C2S 0x02): 1.8 added a varint `type` (0=interact, 1=attack,
//!   2=interact_at + x/y/z floats); 1.7 was `i32 target, i8 mouse`.
//! * Player Digging / Block Placement: 1.7 uses split coords + u8 Y; 1.8 uses
//!   the packed Position.
//! * Update Sign (S2C/C2S): 1.7 sends raw text lines, 1.8 sends JSON chat
//!   components and uses Position.
//! * Window Click: a Transaction ID byte layout changed slightly (no actual
//!   wire-bytes diff — the action enum extended).
//! * Statistics (S2C): 1.7 array of strings; 1.8 array of `(string, varint)`.
//! * Tab Complete (S2C): a different shape (1.8 wraps in count of strings).
//! * Spawn Position (S2C 0x05): coord triple → packed long Position.
//!
//! Internal proxy convention: many "v1_8" packets stored by the proxy after a
//! `modern_to_v1_8` pass still use 1.7-style separate-int coordinates (see
//! `modern_to_v1_8::s2c_block_change` for the canonical example). Because the
//! 1.12.2 → 1.7 path goes `modern_to_v1_8 → v1_8_to_v1_7`, this converter must
//! treat that internal convention as authoritative for the S2C direction.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use kojacoord_protocol::codec::{Decode, Encode};
use kojacoord_protocol::types::VarInt;

use super::{build_payload, split_id};
use crate::converter::ConversionResult;

// ── 1.7 (protocol 5) S2C packet IDs ─────────────────────────────────────────
#[allow(dead_code)]
const V17_S2C_KEEP_ALIVE: u8 = 0x00;
const V17_S2C_JOIN_GAME: u8 = 0x01;
const V17_S2C_CHAT: u8 = 0x02;
const V17_S2C_UPDATE_TIME: u8 = 0x03;
const V17_S2C_EQUIPMENT: u8 = 0x04;
const V17_S2C_SPAWN_POSITION: u8 = 0x05;
const V17_S2C_UPDATE_HEALTH: u8 = 0x06;
const V17_S2C_RESPAWN: u8 = 0x07;
const V17_S2C_PLAYER_POS_LOOK: u8 = 0x08;
const V17_S2C_HELD_ITEM_CHANGE: u8 = 0x09;
const V17_S2C_USE_BED: u8 = 0x0A;
const V17_S2C_ANIMATION: u8 = 0x0B;
const V17_S2C_SPAWN_PLAYER: u8 = 0x0C;
const V17_S2C_COLLECT_ITEM: u8 = 0x0D;
const V17_S2C_SPAWN_OBJECT: u8 = 0x0E;
const V17_S2C_SPAWN_MOB: u8 = 0x0F;
const V17_S2C_SPAWN_PAINTING: u8 = 0x10;
const V17_S2C_SPAWN_EXP_ORB: u8 = 0x11;
const V17_S2C_ENTITY_VELOCITY: u8 = 0x12;
const V17_S2C_ENTITY_DESTROY: u8 = 0x13;
const V17_S2C_ENTITY: u8 = 0x14;
const V17_S2C_ENTITY_REL_MOVE: u8 = 0x15;
const V17_S2C_ENTITY_LOOK: u8 = 0x16;
const V17_S2C_ENTITY_LOOK_REL_MOVE: u8 = 0x17;
const V17_S2C_ENTITY_TELEPORT: u8 = 0x18;
const V17_S2C_ENTITY_HEAD_LOOK: u8 = 0x19;
const V17_S2C_ENTITY_STATUS: u8 = 0x1A;
const V17_S2C_ATTACH_ENTITY: u8 = 0x1B;
const V17_S2C_ENTITY_METADATA: u8 = 0x1C;
const V17_S2C_ENTITY_EFFECT: u8 = 0x1D;
const V17_S2C_REMOVE_ENTITY_EFFECT: u8 = 0x1E;
const V17_S2C_EXPERIENCE: u8 = 0x1F;
const V17_S2C_ENTITY_PROPERTIES: u8 = 0x20;
const V17_S2C_CHUNK_DATA: u8 = 0x21;
const V17_S2C_MULTI_BLOCK_CHANGE: u8 = 0x22;
const V17_S2C_BLOCK_CHANGE: u8 = 0x23;
const V17_S2C_BLOCK_ACTION: u8 = 0x24;
const V17_S2C_BLOCK_BREAK_ANIM: u8 = 0x25;
const V17_S2C_CHUNK_BULK: u8 = 0x26;
const V17_S2C_EXPLOSION: u8 = 0x27;
const V17_S2C_EFFECT: u8 = 0x28;
const V17_S2C_NAMED_SOUND: u8 = 0x29;
const V17_S2C_PARTICLE: u8 = 0x2A;
const V17_S2C_GAME_STATE: u8 = 0x2B;
const V17_S2C_SPAWN_GLOBAL: u8 = 0x2C;
const V17_S2C_OPEN_WINDOW: u8 = 0x2D;
const V17_S2C_CLOSE_WINDOW: u8 = 0x2E;
const V17_S2C_SET_SLOT: u8 = 0x2F;
const V17_S2C_WINDOW_ITEMS: u8 = 0x30;
const V17_S2C_WINDOW_PROPERTY: u8 = 0x31;
const V17_S2C_CONFIRM_TRANSACTION: u8 = 0x32;
const V17_S2C_UPDATE_SIGN: u8 = 0x33;
const V17_S2C_MAP: u8 = 0x34;
const V17_S2C_UPDATE_TILE_ENTITY: u8 = 0x35;
const V17_S2C_OPEN_SIGN_EDITOR: u8 = 0x36;
const V17_S2C_STATISTICS: u8 = 0x37;
const V17_S2C_PLAYER_LIST_ITEM: u8 = 0x38;
const V17_S2C_ABILITIES: u8 = 0x39;
const V17_S2C_TAB_COMPLETE: u8 = 0x3A;
const V17_S2C_SCOREBOARD_OBJ: u8 = 0x3B;
const V17_S2C_SCOREBOARD_SCORE: u8 = 0x3C;
const V17_S2C_DISPLAY_SCOREBOARD: u8 = 0x3D;
const V17_S2C_SCOREBOARD_TEAM: u8 = 0x3E;
const V17_S2C_PLUGIN_MESSAGE: u8 = 0x3F;
const V17_S2C_DISCONNECT: u8 = 0x40;

// ── 1.8 (protocol 47) S2C packet IDs ────────────────────────────────────────
const V18_S2C_KEEP_ALIVE: u8 = 0x00;
const V18_S2C_JOIN_GAME: u8 = 0x01;
const V18_S2C_CHAT: u8 = 0x02;
const V18_S2C_UPDATE_TIME: u8 = 0x03;
const V18_S2C_EQUIPMENT: u8 = 0x04;
const V18_S2C_SPAWN_POSITION: u8 = 0x05;
const V18_S2C_UPDATE_HEALTH: u8 = 0x06;
const V18_S2C_RESPAWN: u8 = 0x07;
const V18_S2C_PLAYER_POS_LOOK: u8 = 0x08;
const V18_S2C_HELD_ITEM_CHANGE: u8 = 0x09;
const V18_S2C_USE_BED: u8 = 0x0A;
const V18_S2C_ANIMATION: u8 = 0x0B;
const V18_S2C_SPAWN_PLAYER: u8 = 0x0C;
const V18_S2C_COLLECT_ITEM: u8 = 0x0D;
const V18_S2C_SPAWN_OBJECT: u8 = 0x0E;
const V18_S2C_SPAWN_MOB: u8 = 0x0F;
const V18_S2C_SPAWN_PAINTING: u8 = 0x10;
const V18_S2C_SPAWN_EXP_ORB: u8 = 0x11;
const V18_S2C_ENTITY_VELOCITY: u8 = 0x12;
const V18_S2C_ENTITY_DESTROY: u8 = 0x13;
const V18_S2C_ENTITY: u8 = 0x14;
const V18_S2C_ENTITY_REL_MOVE: u8 = 0x15;
const V18_S2C_ENTITY_LOOK: u8 = 0x16;
const V18_S2C_ENTITY_LOOK_REL_MOVE: u8 = 0x17;
const V18_S2C_ENTITY_TELEPORT: u8 = 0x18;
const V18_S2C_ENTITY_HEAD_LOOK: u8 = 0x19;
const V18_S2C_ENTITY_STATUS: u8 = 0x1A;
const V18_S2C_ATTACH_ENTITY: u8 = 0x1B;
const V18_S2C_ENTITY_METADATA: u8 = 0x1C;
const V18_S2C_ENTITY_EFFECT: u8 = 0x1D;
const V18_S2C_REMOVE_ENTITY_EFFECT: u8 = 0x1E;
const V18_S2C_EXPERIENCE: u8 = 0x1F;
const V18_S2C_ENTITY_PROPERTIES: u8 = 0x20;
const V18_S2C_CHUNK_DATA: u8 = 0x21;
const V18_S2C_MULTI_BLOCK_CHANGE: u8 = 0x22;
const V18_S2C_BLOCK_CHANGE: u8 = 0x23;
const V18_S2C_BLOCK_ACTION: u8 = 0x24;
const V18_S2C_BLOCK_BREAK_ANIM: u8 = 0x25;
const V18_S2C_CHUNK_BULK: u8 = 0x26;
const V18_S2C_EXPLOSION: u8 = 0x27;
const V18_S2C_EFFECT: u8 = 0x28;
const V18_S2C_NAMED_SOUND: u8 = 0x29;
const V18_S2C_PARTICLE: u8 = 0x2A;
const V18_S2C_GAME_STATE: u8 = 0x2B;
const V18_S2C_SPAWN_GLOBAL: u8 = 0x2C;
const V18_S2C_OPEN_WINDOW: u8 = 0x2D;
const V18_S2C_CLOSE_WINDOW: u8 = 0x2E;
const V18_S2C_SET_SLOT: u8 = 0x2F;
const V18_S2C_WINDOW_ITEMS: u8 = 0x30;
const V18_S2C_WINDOW_PROPERTY: u8 = 0x31;
const V18_S2C_CONFIRM_TRANSACTION: u8 = 0x32;
const V18_S2C_UPDATE_SIGN: u8 = 0x33;
const V18_S2C_MAP: u8 = 0x34;
const V18_S2C_UPDATE_TILE_ENTITY: u8 = 0x35;
const V18_S2C_OPEN_SIGN_EDITOR: u8 = 0x36;
const V18_S2C_STATISTICS: u8 = 0x37;
const V18_S2C_PLAYER_LIST_ITEM: u8 = 0x38;
const V18_S2C_ABILITIES: u8 = 0x39;
const V18_S2C_TAB_COMPLETE: u8 = 0x3A;
const V18_S2C_SCOREBOARD_OBJ: u8 = 0x3B;
const V18_S2C_SCOREBOARD_SCORE: u8 = 0x3C;
const V18_S2C_DISPLAY_SCOREBOARD: u8 = 0x3D;
const V18_S2C_SCOREBOARD_TEAM: u8 = 0x3E;
const V18_S2C_PLUGIN_MESSAGE: u8 = 0x3F;
const V18_S2C_DISCONNECT: u8 = 0x40;
const V18_S2C_SERVER_DIFFICULTY: u8 = 0x41;
const V18_S2C_COMBAT_EVENT: u8 = 0x42;
const V18_S2C_CAMERA: u8 = 0x43;
const V18_S2C_WORLD_BORDER: u8 = 0x44;
const V18_S2C_TITLE: u8 = 0x45;
const V18_S2C_PLAYER_LIST_HEADER_FOOTER: u8 = 0x47;
const V18_S2C_RESOURCE_PACK: u8 = 0x48;

// ── 1.7 (protocol 5) C2S packet IDs ─────────────────────────────────────────
const V17_C2S_KEEP_ALIVE: u8 = 0x00;
const V17_C2S_CHAT: u8 = 0x01;
const V17_C2S_USE_ENTITY: u8 = 0x02;
const V17_C2S_PLAYER_ON_GROUND: u8 = 0x03;
const V17_C2S_PLAYER_POS: u8 = 0x04;
const V17_C2S_PLAYER_LOOK: u8 = 0x05;
const V17_C2S_PLAYER_POS_LOOK: u8 = 0x06;
const V17_C2S_PLAYER_DIGGING: u8 = 0x07;
const V17_C2S_PLAYER_BLOCK_PLACE: u8 = 0x08;
const V17_C2S_HELD_ITEM: u8 = 0x09;
const V17_C2S_ANIMATION: u8 = 0x0A;
const V17_C2S_ENTITY_ACTION: u8 = 0x0B;
const V17_C2S_STEER_VEHICLE: u8 = 0x0C;
const V17_C2S_CLOSE_WINDOW: u8 = 0x0D;
const V17_C2S_WINDOW_CLICK: u8 = 0x0E;
const V17_C2S_CONFIRM_TRANSACTION: u8 = 0x0F;
const V17_C2S_CREATIVE_INV: u8 = 0x10;
const V17_C2S_ENCHANT_ITEM: u8 = 0x11;
const V17_C2S_UPDATE_SIGN: u8 = 0x12;
const V17_C2S_PLAYER_ABILITIES: u8 = 0x13;
const V17_C2S_TAB_COMPLETE: u8 = 0x14;
const V17_C2S_SETTINGS: u8 = 0x15;
const V17_C2S_CLIENT_STATUS: u8 = 0x16;
const V17_C2S_PLUGIN_MESSAGE: u8 = 0x17;

// ── 1.8 (protocol 47) C2S packet IDs ────────────────────────────────────────
const V18_C2S_KEEP_ALIVE: u8 = 0x00;
const V18_C2S_CHAT: u8 = 0x01;
const V18_C2S_USE_ENTITY: u8 = 0x02;
const V18_C2S_PLAYER_ON_GROUND: u8 = 0x03;
const V18_C2S_PLAYER_POS: u8 = 0x04;
const V18_C2S_PLAYER_LOOK: u8 = 0x05;
const V18_C2S_PLAYER_POS_LOOK: u8 = 0x06;
const V18_C2S_PLAYER_DIGGING: u8 = 0x07;
const V18_C2S_PLAYER_BLOCK_PLACE: u8 = 0x08;
const V18_C2S_HELD_ITEM: u8 = 0x09;
const V18_C2S_ANIMATION: u8 = 0x0A;
const V18_C2S_ENTITY_ACTION: u8 = 0x0B;
const V18_C2S_STEER_VEHICLE: u8 = 0x0C;
const V18_C2S_CLOSE_WINDOW: u8 = 0x0D;
const V18_C2S_WINDOW_CLICK: u8 = 0x0E;
const V18_C2S_CONFIRM_TRANSACTION: u8 = 0x0F;
const V18_C2S_CREATIVE_INV: u8 = 0x10;
const V18_C2S_ENCHANT_ITEM: u8 = 0x11;
const V18_C2S_UPDATE_SIGN: u8 = 0x12;
const V18_C2S_PLAYER_ABILITIES: u8 = 0x13;
const V18_C2S_TAB_COMPLETE: u8 = 0x14;
const V18_C2S_SETTINGS: u8 = 0x15;
const V18_C2S_CLIENT_STATUS: u8 = 0x16;
const V18_C2S_PLUGIN_MESSAGE: u8 = 0x17;
const V18_C2S_SPECTATE: u8 = 0x18;
const V18_C2S_RESOURCE_PACK_STATUS: u8 = 0x19;

// ──────────────────────────────────────────────────────────────────────────
// S2C: 1.7 server → 1.8 client
// ──────────────────────────────────────────────────────────────────────────

pub fn convert_s2c(payload: Bytes) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    match id {
        V17_S2C_KEEP_ALIVE => ConversionResult::Passthrough,
        V17_S2C_JOIN_GAME => s2c_join_game(body),
        V17_S2C_CHAT => s2c_chat(body),
        V17_S2C_UPDATE_TIME => ConversionResult::Passthrough,
        V17_S2C_EQUIPMENT => s2c_equipment(body),
        V17_S2C_SPAWN_POSITION => s2c_spawn_position(body),
        V17_S2C_UPDATE_HEALTH => s2c_update_health(body),
        V17_S2C_RESPAWN => s2c_respawn(body),
        V17_S2C_PLAYER_POS_LOOK => s2c_player_pos_look(body),
        V17_S2C_HELD_ITEM_CHANGE => ConversionResult::Passthrough,
        V17_S2C_USE_BED => s2c_use_bed(body),
        V17_S2C_ANIMATION => ConversionResult::Passthrough,
        V17_S2C_SPAWN_PLAYER => s2c_spawn_player(body),
        V17_S2C_COLLECT_ITEM => ConversionResult::Passthrough,
        V17_S2C_SPAWN_OBJECT => ConversionResult::Passthrough,
        V17_S2C_SPAWN_MOB => ConversionResult::Passthrough,
        V17_S2C_SPAWN_PAINTING => s2c_spawn_painting(body),
        V17_S2C_SPAWN_EXP_ORB => ConversionResult::Passthrough,
        V17_S2C_ENTITY_VELOCITY => s2c_entity_velocity(body),
        V17_S2C_ENTITY_DESTROY => s2c_entity_destroy(body),
        V17_S2C_ENTITY => s2c_entity(body),
        V17_S2C_ENTITY_REL_MOVE => s2c_entity_rel_move(body),
        V17_S2C_ENTITY_LOOK => s2c_entity_look(body),
        V17_S2C_ENTITY_LOOK_REL_MOVE => s2c_entity_look_rel_move(body),
        V17_S2C_ENTITY_TELEPORT => s2c_entity_teleport(body),
        V17_S2C_ENTITY_HEAD_LOOK => s2c_entity_head_look(body),
        V17_S2C_ENTITY_STATUS => ConversionResult::Passthrough,
        V17_S2C_ATTACH_ENTITY => ConversionResult::Passthrough,
        V17_S2C_ENTITY_METADATA => ConversionResult::Passthrough,
        V17_S2C_ENTITY_EFFECT => s2c_entity_effect(body),
        V17_S2C_REMOVE_ENTITY_EFFECT => s2c_remove_entity_effect(body),
        V17_S2C_EXPERIENCE => s2c_experience(body),
        V17_S2C_ENTITY_PROPERTIES => s2c_entity_properties(body),
        V17_S2C_CHUNK_DATA => s2c_chunk_data(body),
        V17_S2C_MULTI_BLOCK_CHANGE => s2c_multi_block_change(body),
        V17_S2C_BLOCK_CHANGE => {
            ConversionResult::Converted(vec![build_payload(V18_S2C_BLOCK_CHANGE, &body)])
        },
        V17_S2C_BLOCK_ACTION => s2c_block_action(body),
        V17_S2C_BLOCK_BREAK_ANIM => s2c_block_break_anim(body),
        V17_S2C_CHUNK_BULK => {
            tracing::debug!(target: "converter", "v1_7→v1_8: chunk bulk packet dropped (incompatible chunk format)");
            ConversionResult::Drop
        },
        V17_S2C_EXPLOSION => ConversionResult::Passthrough,
        V17_S2C_EFFECT => s2c_effect(body),
        V17_S2C_NAMED_SOUND => ConversionResult::Passthrough,
        V17_S2C_PARTICLE => {
            tracing::debug!(target: "converter", "v1_7→v1_8: particle packet dropped (string→id mapping needed)");
            ConversionResult::Drop
        },
        V17_S2C_GAME_STATE => ConversionResult::Passthrough,
        V17_S2C_SPAWN_GLOBAL => ConversionResult::Passthrough,
        V17_S2C_OPEN_WINDOW => s2c_open_window(body),
        V17_S2C_CLOSE_WINDOW => ConversionResult::Passthrough,
        V17_S2C_SET_SLOT => ConversionResult::Passthrough,
        V17_S2C_WINDOW_ITEMS => ConversionResult::Passthrough,
        V17_S2C_WINDOW_PROPERTY => ConversionResult::Passthrough,
        V17_S2C_CONFIRM_TRANSACTION => ConversionResult::Passthrough,
        V17_S2C_UPDATE_SIGN => s2c_update_sign(body),
        V17_S2C_MAP => {
            tracing::debug!(target: "converter", "v1_7→v1_8: map packet dropped (incompatible map format)");
            ConversionResult::Drop
        },
        V17_S2C_UPDATE_TILE_ENTITY => s2c_update_tile_entity(body),
        V17_S2C_OPEN_SIGN_EDITOR => s2c_open_sign_editor(body),
        V17_S2C_STATISTICS => ConversionResult::Passthrough,
        V17_S2C_PLAYER_LIST_ITEM => {
            tracing::debug!(target: "converter", "v1_7→v1_8: player list item dropped (action-based format added in 1.8)");
            ConversionResult::Drop
        },
        V17_S2C_ABILITIES => ConversionResult::Passthrough,
        V17_S2C_TAB_COMPLETE => s2c_tab_complete(body),
        V17_S2C_SCOREBOARD_OBJ => ConversionResult::Passthrough,
        V17_S2C_SCOREBOARD_SCORE => ConversionResult::Passthrough,
        V17_S2C_DISPLAY_SCOREBOARD => ConversionResult::Passthrough,
        V17_S2C_SCOREBOARD_TEAM => s2c_scoreboard_team(body),
        V17_S2C_PLUGIN_MESSAGE => ConversionResult::Passthrough,
        V17_S2C_DISCONNECT => ConversionResult::Passthrough,
        _ => ConversionResult::Passthrough,
    }
}

fn s2c_join_game(body: Bytes) -> ConversionResult {
    // 1.7: i32 eid; u8 gamemode; i8 dimension; u8 difficulty; u8 maxPlayers; string levelType
    // 1.8: same + bool reduced_debug_info trailing byte.
    if body.is_empty() {
        return ConversionResult::Passthrough;
    }
    let mut out = BytesMut::with_capacity(body.len() + 1);
    out.extend_from_slice(&body);
    out.put_u8(0);
    ConversionResult::Converted(vec![build_payload(V18_S2C_JOIN_GAME, &out)])
}

fn s2c_chat(body: Bytes) -> ConversionResult {
    // 1.7: string json. 1.8: string json + u8 position.
    let mut out = BytesMut::with_capacity(body.len() + 1);
    out.extend_from_slice(&body);
    out.put_u8(0); // chat box
    ConversionResult::Converted(vec![build_payload(V18_S2C_CHAT, &out)])
}

fn s2c_spawn_position(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 x; i32 y; i32 z. 1.8: packed Position (i64).
    //
    // The 1.8 packed layout puts Y in the MIDDLE 12 bits (26..37) per
    // `kojacoord_protocol::types::position::encode_legacy_position`:
    //   `((x & 0x3FFFFFF) << 38) | ((y & 0xFFF) << 26) | (z & 0x3FFFFFF)`.
    // 1.14+ moved Y to the LOW 12 bits. The previous code here used the
    // 1.14+ packing for a 1.8 target → every 1.8 client receiving a
    // SpawnPosition spawned at the wrong block (Y and Z bits crossed).
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
    ConversionResult::Converted(vec![build_payload(V18_S2C_SPAWN_POSITION, &out)])
}

fn s2c_player_pos_look(mut body: Bytes) -> ConversionResult {
    // 1.7 wire: f64 x; f64 stance; f64 y; f64 z; f32 yaw; f32 pitch; u8 onGround.
    // 1.8 wire: f64 x; f64 y; f64 z; f32 yaw; f32 pitch; u8 flags.
    if body.remaining() < 41 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_f64();
    let _stance = body.get_f64();
    let y = body.get_f64();
    let z = body.get_f64();
    let yaw = body.get_f32();
    let pitch = body.get_f32();
    let _on_ground = body.get_u8();

    let mut out = BytesMut::with_capacity(33);
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_f32(yaw);
    out.put_f32(pitch);
    out.put_u8(0);
    ConversionResult::Converted(vec![build_payload(V18_S2C_PLAYER_POS_LOOK, &out)])
}

fn s2c_entity(mut body: Bytes) -> ConversionResult {
    // 1.7 Entity (0x14): i32 entity_id. 1.8 (0x14): VarInt entity_id.
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mut out = BytesMut::with_capacity(5);
    VarInt(eid).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V18_S2C_ENTITY, &out)])
}

fn s2c_entity_velocity(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 entityId; i16 vx; i16 vy; i16 vz. 1.8: VarInt entityId; i16 vx; i16 vy; i16 vz.
    if body.remaining() < 10 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mut out = BytesMut::with_capacity(body.len() + 4);
    VarInt(eid).encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V18_S2C_ENTITY_VELOCITY, &out)])
}

fn s2c_entity_rel_move(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 entityId; i8 dx; i8 dy; i8 dz. 1.8: VarInt entityId; i8 dx; i8 dy; i8 dz; bool onGround.
    if body.remaining() < 6 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mut out = BytesMut::with_capacity(body.len() + 2);
    VarInt(eid).encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    out.put_u8(1);
    ConversionResult::Converted(vec![build_payload(V18_S2C_ENTITY_REL_MOVE, &out)])
}

fn s2c_entity_look(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 entityId; i8 yaw; i8 pitch. 1.8: VarInt entityId; i8 yaw; i8 pitch; bool onGround.
    if body.remaining() < 6 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mut out = BytesMut::with_capacity(body.len() + 2);
    VarInt(eid).encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    out.put_u8(1);
    ConversionResult::Converted(vec![build_payload(V18_S2C_ENTITY_LOOK, &out)])
}

fn s2c_entity_look_rel_move(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 entityId; i8 dx; i8 dy; i8 dz; i8 yaw; i8 pitch. 1.8: VarInt + same + bool onGround.
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mut out = BytesMut::with_capacity(body.len() + 2);
    VarInt(eid).encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    out.put_u8(1);
    ConversionResult::Converted(vec![build_payload(V18_S2C_ENTITY_LOOK_REL_MOVE, &out)])
}

fn s2c_entity_teleport(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 entityId; i32 x; i32 y; i32 z; i8 yaw; i8 pitch.
    // 1.8: VarInt entityId; i32 x; i32 y; i32 z; i8 yaw; i8 pitch; bool onGround.
    if body.remaining() < 18 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mut out = BytesMut::with_capacity(body.len() + 2);
    VarInt(eid).encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    out.put_u8(1);
    ConversionResult::Converted(vec![build_payload(V18_S2C_ENTITY_TELEPORT, &out)])
}

fn s2c_entity_head_look(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 entityId; i8 headYaw. 1.8: VarInt entityId; i8 headYaw.
    if body.remaining() < 5 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mut out = BytesMut::with_capacity(6);
    VarInt(eid).encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V18_S2C_ENTITY_HEAD_LOOK, &out)])
}

fn s2c_entity_destroy(mut body: Bytes) -> ConversionResult {
    // 1.7: i8 count; i32[] ids. 1.8: varint count; varint[] ids.
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
        let id = body.get_i32();
        VarInt(id).encode(&mut out).unwrap();
    }
    ConversionResult::Converted(vec![build_payload(V18_S2C_ENTITY_DESTROY, &out)])
}

fn s2c_experience(mut body: Bytes) -> ConversionResult {
    // 1.7: f32 bar; i16 level; i16 total. 1.8: f32 bar; varint level; varint total.
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let bar = body.get_f32();
    let level = body.get_i16() as i32;
    let total = body.get_i16() as i32;
    let mut out = BytesMut::new();
    out.put_f32(bar);
    VarInt(level).encode(&mut out).unwrap();
    VarInt(total).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V18_S2C_EXPERIENCE, &out)])
}

fn s2c_update_sign(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 x; i16 y; i32 z; 4 strings. 1.8: Position + 4 chat-JSON strings.
    if body.remaining() < 10 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32() as i64;
    let y = body.get_i16() as i64;
    let z = body.get_i32() as i64;
    // 1.8 packed Position layout = legacy (Y in middle 12 bits).
    // See `kojacoord_protocol::types::encode_legacy_position`.
    let packed = ((x & 0x3FF_FFFF) << 38) | ((y & 0xFFF) << 26) | (z & 0x3FF_FFFF);

    let mut out = BytesMut::new();
    out.put_i64(packed);
    for _ in 0..4 {
        let Ok(line) = String::decode(&mut body) else {
            return ConversionResult::Passthrough;
        };
        let json = format!("{{\"text\":{}}}", json_escape(&line));
        json.encode(&mut out).unwrap();
    }
    ConversionResult::Converted(vec![build_payload(V18_S2C_UPDATE_SIGN, &out)])
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn s2c_tab_complete(mut body: Bytes) -> ConversionResult {
    // 1.7: single string (newline-separated). 1.8: varint count; string[].
    let Ok(joined) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let parts: Vec<&str> = if joined.is_empty() {
        Vec::new()
    } else {
        joined.split('\0').collect()
    };
    let mut out = BytesMut::new();
    VarInt(parts.len() as i32).encode(&mut out).unwrap();
    for p in parts {
        p.to_string().encode(&mut out).unwrap();
    }
    ConversionResult::Converted(vec![build_payload(V18_S2C_TAB_COMPLETE, &out)])
}

fn s2c_scoreboard_team(mut body: Bytes) -> ConversionResult {
    // 1.8 added a "name tag visibility" string after action 0/2.
    let Ok(team_name) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.is_empty() {
        return ConversionResult::Passthrough;
    }
    let action = body[0];
    let mut out = BytesMut::new();
    team_name.encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    if action == 0 || action == 2 {
        "always".to_owned().encode(&mut out).unwrap();
    }
    ConversionResult::Converted(vec![build_payload(V18_S2C_SCOREBOARD_TEAM, &out)])
}

fn s2c_equipment(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 entityId; i16 slot; Slot item. 1.8: VarInt entityId; i16 slot; Slot item.
    if body.remaining() < 6 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mut out = BytesMut::with_capacity(body.len() + 4);
    VarInt(eid).encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V18_S2C_EQUIPMENT, &out)])
}

fn s2c_update_health(mut body: Bytes) -> ConversionResult {
    // 1.7: f32 health; i16 food; f32 saturation. 1.8: f32 health; VarInt food; f32 saturation.
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let health = body.get_f32();
    let food = body.get_i16() as i32;
    let mut out = BytesMut::new();
    out.put_f32(health);
    VarInt(food).encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V18_S2C_UPDATE_HEALTH, &out)])
}

fn s2c_respawn(_body: Bytes) -> ConversionResult {
    // 1.7: i32 dimension; u8 difficulty; u8 gamemode; string levelType.
    // 1.8: i32 dimension; u8 difficulty; u8 gamemode; string levelType.
    // Actually the dimension field is i32 in both (1.7 protocol has it as i32 too per Prismarine).
    // Passthrough is safe here — the wire format is identical.
    ConversionResult::Passthrough
}

fn s2c_use_bed(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 entityId; i32 x; u8 y; i32 z. 1.8: VarInt entityId; Position packed.
    if body.remaining() < 13 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let x = body.get_i32() as i64;
    let y = body.get_u8() as i64;
    let z = body.get_i32() as i64;
    let packed = pack_position_1_8(x, y, z);
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_i64(packed);
    ConversionResult::Converted(vec![build_payload(V18_S2C_USE_BED, &out)])
}

fn s2c_spawn_player(_body: Bytes) -> ConversionResult {
    // 1.7: VarInt entityId; string uuid; string name; properties array; i32 x/y/z; i8 yaw/pitch; i16 currentItem; metadata.
    // 1.8: VarInt entityId; UUID (128-bit); i32 x/y/z; i8 yaw/pitch; i16 currentItem; metadata.
    // The UUID changes from string to 128-bit binary, and the properties array is removed.
    // Too complex to convert safely — the properties array is variable-length.
    tracing::debug!(target: "converter", "v1_7→v1_8: spawn player dropped (UUID format + properties array differ)");
    ConversionResult::Drop
}

fn s2c_spawn_painting(body: Bytes) -> ConversionResult {
    // 1.7: VarInt entityId; string title; i32 x; i32 y; i32 z; i32 direction.
    // 1.8: VarInt entityId; string title; Position packed; u8 direction.
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else {
        return ConversionResult::Passthrough;
    };
    let Some(title) = r.string() else {
        return ConversionResult::Passthrough;
    };
    let Some(x) = r.i32() else {
        return ConversionResult::Passthrough;
    };
    let Some(y) = r.i32() else {
        return ConversionResult::Passthrough;
    };
    let Some(z) = r.i32() else {
        return ConversionResult::Passthrough;
    };
    let direction = r.i32().unwrap_or(0) as u8;

    let packed = pack_position_1_8(x as i64, y as i64, z as i64);
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    title.encode(&mut out).unwrap();
    out.put_i64(packed);
    out.put_u8(direction);
    ConversionResult::Converted(vec![build_payload(V18_S2C_SPAWN_PAINTING, &out)])
}

fn s2c_entity_effect(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 entityId; i8 effectId; i8 amplifier; i16 duration.
    // 1.8: VarInt entityId; i8 effectId; i8 amplifier; VarInt duration; bool hideParticles.
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let effect_id = body.get_i8();
    let amplifier = body.get_i8();
    let duration = body.get_i16() as i32;
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_i8(effect_id);
    out.put_i8(amplifier);
    VarInt(duration).encode(&mut out).unwrap();
    out.put_u8(0);
    ConversionResult::Converted(vec![build_payload(V18_S2C_ENTITY_EFFECT, &out)])
}

fn s2c_remove_entity_effect(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 entityId; i8 effectId. 1.8: VarInt entityId; i8 effectId.
    if body.remaining() < 5 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mut out = BytesMut::with_capacity(6);
    VarInt(eid).encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V18_S2C_REMOVE_ENTITY_EFFECT, &out)])
}

fn s2c_entity_properties(body: Bytes) -> ConversionResult {
    // 1.7: i32 entityId; i32 propCount; for each: string key; f64 value; i16 modCount; (UUID f64 i8)*modCount.
    // 1.8: VarInt entityId; i32 propCount; for each: string key; f64 value; VarInt modCount; (UUID f64 i8)*modCount.
    let mut r = super::safe::Reader::new(body.clone());
    let Some(eid) = r.i32() else {
        return ConversionResult::Passthrough;
    };
    let Some(prop_count) = r.i32() else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_i32(prop_count);
    for _ in 0..prop_count {
        let Some(key) = r.string() else {
            return ConversionResult::Passthrough;
        };
        let Some(value) = r.f64() else {
            return ConversionResult::Passthrough;
        };
        let Some(mod_count) = r.i16() else {
            return ConversionResult::Passthrough;
        };
        key.encode(&mut out).unwrap();
        out.put_f64(value);
        VarInt(mod_count as i32).encode(&mut out).unwrap();
        for _ in 0..mod_count {
            let Some(uuid_msb) = r.i64() else {
                return ConversionResult::Passthrough;
            };
            let Some(uuid_lsb) = r.i64() else {
                return ConversionResult::Passthrough;
            };
            let Some(amount) = r.f64() else {
                return ConversionResult::Passthrough;
            };
            let Some(op) = r.i8() else {
                return ConversionResult::Passthrough;
            };
            out.put_i64(uuid_msb);
            out.put_i64(uuid_lsb);
            out.put_f64(amount);
            out.put_i8(op);
        }
    }
    ConversionResult::Converted(vec![build_payload(V18_S2C_ENTITY_PROPERTIES, &out)])
}

fn s2c_chunk_data(_body: Bytes) -> ConversionResult {
    // 1.7: i32 x; i32 z; bool groundUp; u16 bitMap; u16 addBitMap; compressedChunkData.
    // 1.8: i32 x; i32 z; bool groundUp; u16 bitMap; chunkData (varint-prefixed).
    // 1.7 has addBitMap field and i32-prefixed chunk data; 1.8 drops addBitMap and uses varint prefix.
    // Chunk format is incompatible — drop.
    tracing::debug!(target: "converter", "v1_7→v1_8: chunk data dropped (incompatible chunk format)");
    ConversionResult::Drop
}

fn s2c_multi_block_change(_body: Bytes) -> ConversionResult {
    // 1.7: i32 chunkX; i32 chunkZ; i16 recordCount; i32 dataLength; records.
    // 1.8: i32 chunkX; i32 chunkZ; VarInt recordCount; records (different format).
    // Incompatible record format — drop.
    tracing::debug!(target: "converter", "v1_7→v1_8: multi block change dropped (incompatible record format)");
    ConversionResult::Drop
}

fn s2c_block_action(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 x; i16 y; i32 z; u8 byte1; u8 byte2; VarInt blockId.
    // 1.8: Position packed; u8 byte1; u8 byte2; VarInt blockId.
    if body.remaining() < 11 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32() as i64;
    let y = body.get_i16() as i64;
    let z = body.get_i32() as i64;
    let packed = pack_position_1_8(x, y, z);
    let mut out = BytesMut::with_capacity(12);
    out.put_i64(packed);
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V18_S2C_BLOCK_ACTION, &out)])
}

fn s2c_block_break_anim(body: Bytes) -> ConversionResult {
    // 1.7: VarInt entityId; i32 x; i32 y; i32 z; i8 destroyStage.
    // 1.8: VarInt entityId; Position packed; i8 destroyStage.
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else {
        return ConversionResult::Passthrough;
    };
    let Some(x) = r.i32() else {
        return ConversionResult::Passthrough;
    };
    let Some(y) = r.i32() else {
        return ConversionResult::Passthrough;
    };
    let Some(z) = r.i32() else {
        return ConversionResult::Passthrough;
    };
    let Some(stage) = r.i8() else {
        return ConversionResult::Passthrough;
    };
    let packed = pack_position_1_8(x as i64, y as i64, z as i64);
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_i64(packed);
    out.put_i8(stage);
    ConversionResult::Converted(vec![build_payload(V18_S2C_BLOCK_BREAK_ANIM, &out)])
}

fn s2c_effect(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 effectId; i32 x; u8 y; i32 z; i32 data; bool global.
    // 1.8: i32 effectId; Position packed; i32 data; bool global.
    if body.remaining() < 15 {
        return ConversionResult::Passthrough;
    }
    let effect_id = body.get_i32();
    let x = body.get_i32() as i64;
    let y = body.get_u8() as i64;
    let z = body.get_i32() as i64;
    let packed = pack_position_1_8(x, y, z);
    let mut out = BytesMut::with_capacity(18);
    out.put_i32(effect_id);
    out.put_i64(packed);
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V18_S2C_EFFECT, &out)])
}

fn s2c_open_window(mut body: Bytes) -> ConversionResult {
    // 1.7: u8 windowId; u8 inventoryType; string windowTitle; u8 slotCount; bool useProvidedTitle; [if type==11: i32 entityId].
    // 1.8: u8 windowId; string inventoryType; string windowTitle; u8 slotCount; [if type=="EntityHorse": i32 entityId].
    // The inventory type changes from u8 to string. This is a significant structural change.
    if body.remaining() < 3 {
        return ConversionResult::Passthrough;
    }
    let window_id = body.get_u8();
    let inv_type_id = body.get_u8();
    let inv_type_name = match inv_type_id {
        0 => "minecraft:chest",
        1 => "minecraft:crafting_table",
        2 => "minecraft:furnace",
        3 => "minecraft:dispenser",
        4 => "minecraft:enchanting_table",
        5 => "minecraft:brewing_stand",
        6 => "minecraft:villager",
        7 => "minecraft:beacon",
        8 => "minecraft:anvil",
        9 => "minecraft:hopper",
        10 => "minecraft:dropper",
        11 => "EntityHorse",
        _ => "minecraft:chest",
    };
    let mut out = BytesMut::new();
    out.put_u8(window_id);
    inv_type_name.to_owned().encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V18_S2C_OPEN_WINDOW, &out)])
}

fn s2c_update_tile_entity(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 x; i16 y; i32 z; u8 action; nbtData.
    // 1.8: Position packed; u8 action; nbtData.
    if body.remaining() < 10 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32() as i64;
    let y = body.get_i16() as i64;
    let z = body.get_i32() as i64;
    let packed = pack_position_1_8(x, y, z);
    let mut out = BytesMut::with_capacity(10);
    out.put_i64(packed);
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V18_S2C_UPDATE_TILE_ENTITY, &out)])
}

fn s2c_open_sign_editor(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 x; i32 y; i32 z. 1.8: Position packed.
    if body.remaining() < 12 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32() as i64;
    let y = body.get_i32() as i64;
    let z = body.get_i32() as i64;
    let packed = pack_position_1_8(x, y, z);
    let mut out = BytesMut::with_capacity(8);
    out.put_i64(packed);
    ConversionResult::Converted(vec![build_payload(V18_S2C_OPEN_SIGN_EDITOR, &out)])
}

fn pack_position_1_8(x: i64, y: i64, z: i64) -> i64 {
    ((x & 0x3FF_FFFF) << 38) | ((y & 0xFFF) << 26) | (z & 0x3FF_FFFF)
}

// ──────────────────────────────────────────────────────────────────────────
// C2S: 1.7 client → 1.8 server
// ──────────────────────────────────────────────────────────────────────────

pub fn convert_c2s(payload: Bytes) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    match id {
        V17_C2S_KEEP_ALIVE => ConversionResult::Passthrough,
        V17_C2S_CHAT => ConversionResult::Passthrough,
        V17_C2S_USE_ENTITY => c2s_use_entity(body),
        V17_C2S_PLAYER_ON_GROUND => ConversionResult::Passthrough,
        V17_C2S_PLAYER_POS => ConversionResult::Passthrough,
        V17_C2S_PLAYER_LOOK => ConversionResult::Passthrough,
        V17_C2S_PLAYER_POS_LOOK => c2s_player_pos_look(body),
        V17_C2S_PLAYER_DIGGING => c2s_player_digging(body),
        V17_C2S_PLAYER_BLOCK_PLACE => c2s_player_block_place(body),
        V17_C2S_HELD_ITEM => ConversionResult::Passthrough,
        V17_C2S_ANIMATION => ConversionResult::Passthrough,
        V17_C2S_ENTITY_ACTION => ConversionResult::Passthrough,
        V17_C2S_STEER_VEHICLE => ConversionResult::Passthrough,
        V17_C2S_CLOSE_WINDOW => ConversionResult::Passthrough,
        V17_C2S_WINDOW_CLICK => ConversionResult::Passthrough,
        V17_C2S_CONFIRM_TRANSACTION => ConversionResult::Passthrough,
        V17_C2S_CREATIVE_INV => ConversionResult::Passthrough,
        V17_C2S_ENCHANT_ITEM => ConversionResult::Passthrough,
        V17_C2S_UPDATE_SIGN => c2s_update_sign(body),
        V17_C2S_PLAYER_ABILITIES => ConversionResult::Passthrough,
        V17_C2S_TAB_COMPLETE => ConversionResult::Passthrough,
        V17_C2S_SETTINGS => ConversionResult::Passthrough,
        V17_C2S_CLIENT_STATUS => ConversionResult::Passthrough,
        V17_C2S_PLUGIN_MESSAGE => ConversionResult::Passthrough,
        _ => ConversionResult::Passthrough,
    }
}

fn c2s_use_entity(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 target; i8 mouse (0=right click, 1=left click). 1.8: varint target; varint type.
    if body.remaining() < 5 {
        return ConversionResult::Passthrough;
    }
    let target = body.get_i32();
    let mouse = body.get_i8();
    let typ = if mouse == 1 { 1 } else { 0 };

    let mut out = BytesMut::new();
    VarInt(target).encode(&mut out).unwrap();
    VarInt(typ).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V18_C2S_USE_ENTITY, &out)])
}

fn c2s_player_pos_look(mut body: Bytes) -> ConversionResult {
    // 1.7 C2S 0x06: f64 x; f64 feet_y; f64 stance; f64 z; f32 yaw; f32 pitch; bool on_ground.
    // 1.8 C2S 0x06: f64 x; f64 feet_y; f64 z; f32 yaw; f32 pitch; bool on_ground.
    if body.remaining() < 41 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_f64();
    let y = body.get_f64();
    let _stance = body.get_f64();
    let z = body.get_f64();
    let yaw = body.get_f32();
    let pitch = body.get_f32();
    let on_ground = body.get_u8();

    let mut out = BytesMut::with_capacity(33);
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_f32(yaw);
    out.put_f32(pitch);
    out.put_u8(on_ground);
    ConversionResult::Converted(vec![build_payload(V18_C2S_PLAYER_POS_LOOK, &out)])
}

fn c2s_player_digging(mut body: Bytes) -> ConversionResult {
    // 1.7: i8 status; i32 x; u8 y; i32 z; i8 face.
    // 1.8: i8 status; Position; i8 face.
    if body.remaining() < 11 {
        return ConversionResult::Passthrough;
    }
    let status = body.get_i8();
    let x = body.get_i32() as i64;
    let y = body.get_u8() as i64;
    let z = body.get_i32() as i64;
    let face = body.get_i8();

    // 1.8 packed Position layout = legacy (Y in middle 12 bits).
    // See `kojacoord_protocol::types::encode_legacy_position`.
    let packed = ((x & 0x3FF_FFFF) << 38) | ((y & 0xFFF) << 26) | (z & 0x3FF_FFFF);
    let mut out = BytesMut::new();
    out.put_i8(status);
    out.put_i64(packed);
    out.put_i8(face);
    ConversionResult::Converted(vec![build_payload(V18_C2S_PLAYER_DIGGING, &out)])
}

fn c2s_player_block_place(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 x; u8 y; i32 z; i8 dir; legacy_slot held; i8 cx; i8 cy; i8 cz.
    // 1.8: Position; i8 dir; legacy_slot held; i8 cx; i8 cy; i8 cz.
    if body.remaining() < 10 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32() as i64;
    let y = body.get_u8() as i64;
    let z = body.get_i32() as i64;
    let dir = body.get_i8();
    // 1.8 packed Position layout = legacy (Y in middle 12 bits).
    // See `kojacoord_protocol::types::encode_legacy_position`.
    let packed = ((x & 0x3FF_FFFF) << 38) | ((y & 0xFFF) << 26) | (z & 0x3FF_FFFF);

    let mut out = BytesMut::new();
    out.put_i64(packed);
    out.put_i8(dir);
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V18_C2S_PLAYER_BLOCK_PLACE, &out)])
}

fn c2s_update_sign(mut body: Bytes) -> ConversionResult {
    // 1.7: i32 x; i16 y; i32 z; 4 strings. 1.8: Position; 4 chat-JSON strings.
    if body.remaining() < 10 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32() as i64;
    let y = body.get_i16() as i64;
    let z = body.get_i32() as i64;
    // 1.8 packed Position layout = legacy (Y in middle 12 bits).
    // See `kojacoord_protocol::types::encode_legacy_position`.
    let packed = ((x & 0x3FF_FFFF) << 38) | ((y & 0xFFF) << 26) | (z & 0x3FF_FFFF);

    let mut out = BytesMut::new();
    out.put_i64(packed);
    for _ in 0..4 {
        let Ok(line) = String::decode(&mut body) else {
            return ConversionResult::Passthrough;
        };
        let json = format!("{{\"text\":{}}}", json_escape(&line));
        json.encode(&mut out).unwrap();
    }
    ConversionResult::Converted(vec![build_payload(V18_C2S_UPDATE_SIGN, &out)])
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_one(r: ConversionResult) -> Bytes {
        match r {
            ConversionResult::Converted(mut v) => {
                assert_eq!(v.len(), 1);
                v.remove(0)
            },
            _ => panic!("expected Converted"),
        }
    }

    fn pack_pos(x: i64, y: i64, z: i64) -> i64 {
        // Test helper — matches the converter's 1.8 packed Position layout
        // (legacy: Y in middle 12 bits).
        ((x & 0x3FF_FFFF) << 38) | ((y & 0xFFF) << 26) | (z & 0x3FF_FFFF)
    }

    #[test]
    fn position_roundtrip_via_spawn_position() {
        // 1.7 sends (10, 64, -3); 1.8 should receive packed Position with same coords.
        let mut body = BytesMut::new();
        body.put_i32(10);
        body.put_i32(64);
        body.put_i32(-3);
        let r = s2c_spawn_position(body.freeze());
        let pkt = decode_one(r);
        let (id, mut rest) = split_id(pkt).unwrap();
        assert_eq!(id, V18_S2C_SPAWN_POSITION);
        let packed = rest.get_i64();
        assert_eq!(packed, pack_pos(10, 64, -3));
    }

    #[test]
    fn chat_appends_position_byte() {
        let mut body = BytesMut::new();
        "hello".to_owned().encode(&mut body).unwrap();
        let r = s2c_chat(body.freeze());
        let pkt = decode_one(r);
        let (id, mut rest) = split_id(pkt).unwrap();
        assert_eq!(id, V18_S2C_CHAT);
        let s = String::decode(&mut rest).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(rest.get_u8(), 0);
    }

    #[test]
    fn player_pos_look_drops_stance() {
        let mut body = BytesMut::new();
        body.put_f64(1.0); // x
        body.put_f64(72.62); // stance
        body.put_f64(71.0); // y
        body.put_f64(2.0); // z
        body.put_f32(90.0);
        body.put_f32(0.0);
        body.put_u8(1);
        let r = s2c_player_pos_look(body.freeze());
        let pkt = decode_one(r);
        let (id, mut rest) = split_id(pkt).unwrap();
        assert_eq!(id, V18_S2C_PLAYER_POS_LOOK);
        assert_eq!(rest.get_f64(), 1.0);
        assert_eq!(rest.get_f64(), 71.0);
        assert_eq!(rest.get_f64(), 2.0);
        assert_eq!(rest.get_f32(), 90.0);
        assert_eq!(rest.get_f32(), 0.0);
        assert_eq!(rest.get_u8(), 0);
    }

    #[test]
    fn entity_destroy_widens_count_and_ids() {
        let mut body = BytesMut::new();
        body.put_i8(2);
        body.put_i32(42);
        body.put_i32(7);
        let r = s2c_entity_destroy(body.freeze());
        let pkt = decode_one(r);
        let (id, mut rest) = split_id(pkt).unwrap();
        assert_eq!(id, V18_S2C_ENTITY_DESTROY);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 2);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 42);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 7);
    }

    #[test]
    fn c2s_digging_uses_packed_position() {
        let mut body = BytesMut::new();
        body.put_i8(0); // status: started digging
        body.put_i32(100); // x
        body.put_u8(64); // y
        body.put_i32(-50); // z
        body.put_i8(1); // face
        let r = c2s_player_digging(body.freeze());
        let pkt = decode_one(r);
        let (id, mut rest) = split_id(pkt).unwrap();
        assert_eq!(id, V18_C2S_PLAYER_DIGGING);
        assert_eq!(rest.get_i8(), 0);
        assert_eq!(rest.get_i64(), pack_pos(100, 64, -50));
        assert_eq!(rest.get_i8(), 1);
    }
}
