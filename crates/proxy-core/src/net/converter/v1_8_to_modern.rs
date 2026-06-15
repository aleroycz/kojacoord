//! 1.8 (protocol 47) → modern serverbound (clientbound-to-server) converter.
//!
//! The proxy's "fully supported" reference is the 1.9 → 1.12.2 epoch
//! (canonical 1.12.2, protocol 340). This file is the primary path used when
//! a legacy 1.8 PvP client is talking to a 1.12.2 (or any 1.9–1.12) backend.
//!
//! Authoritative sources used to derive the tables and field transforms below:
//!   * Java Edition protocol — minecraft.wiki/w/Java_Edition_protocol/Packets
//!   * Protocol history — minecraft.wiki/w/Java_Edition_protocol_history
//!   * PrismarineJS minecraft-data pc/1.8/protocol.json and
//!     pc/1.12.2/protocol.json (authoritative packet shapes).
//!
//! ── Serverbound (client → server) packet-id mapping table ────────────────
//!   name                        1.8     1.12.2   field xform?
//!   KeepAlive                   0x00    0x0B     VarInt → i64
//!   ChatMessage                 0x01    0x02     none
//!   UseEntity / Interact        0x02    0x0A     append hand VarInt (no offhand in 1.8)
//!   Player (on-ground only)     0x03    0x0F     none
//!   PlayerPosition              0x04    0x0C     none
//!   PlayerLook                  0x05    0x0E     none
//!   PlayerPosLook               0x06    0x0D     none
//!   PlayerDigging / PlayerAction 0x07   0x13     status u8→VarInt, x/y/z → Position, face i8→VarInt
//!   PlayerBlockPlacement        0x08    0x1F     reshape (see fn comments)
//!   HeldItemChange              0x09    0x1A     none (both i16)
//!   Animation                   0x0A    0x1D     append hand VarInt
//!   EntityAction                0x0B    0x15     i32+u8+i32 → VarInt+VarInt+VarInt
//!   SteerVehicle                0x0C    0x16     none
//!   CloseWindow                 0x0D    0x08     none
//!   WindowClick / ClickWindow   0x0E    0x07     none
//!   ConfirmTransaction          0x0F    0x05     none
//!   CreativeInventoryAction     0x10    0x1B     legacy slot identical in 1.12.2
//!   EnchantItem                 0x11    0x06     none
//!   UpdateSign                  0x12    0x1C     x/y/z → Position
//!   PlayerAbilities             0x13    0x12     none
//!   TabComplete / Suggestion    0x14    0x01     reshape (assume_command + has_pos)
//!   ClientSettings              0x15    0x04     append main_hand VarInt
//!   ClientStatus                0x16    0x03     none
//!   PluginMessage               0x17    0x09     none
//!   Spectate                    0x18    0x1E     none
//!   ResourcePackStatus          0x19    0x18     none

#![allow(dead_code)] // packet-id constants below are kept as a reference table

use bytes::{Buf, BufMut, Bytes, BytesMut};
use kojacoord_protocol::codec::{Decode, Encode};
use kojacoord_protocol::types::{slot::LegacySlot, VarInt};
use kojacoord_protocol::{Epoch, ProtocolVersion};

use super::{build_payload, nearest, split_id};
use crate::converter::ConversionResult;

// ─── 1.8 serverbound packet IDs (protocol 47) ─────────────────────────────

const V18_C2S_KEEP_ALIVE: u8 = 0x00;
const V18_C2S_CHAT: u8 = 0x01;
const V18_C2S_USE_ENTITY: u8 = 0x02;
const V18_C2S_PLAYER_ON_GROUND: u8 = 0x03;
const V18_C2S_PLAYER_POS: u8 = 0x04;
const V18_C2S_PLAYER_LOOK: u8 = 0x05;
const V18_C2S_PLAYER_POS_LOOK: u8 = 0x06;
const V18_C2S_DIGGING: u8 = 0x07;
const V18_C2S_BLOCK_PLACE: u8 = 0x08;
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

// ─── 1.12.2 serverbound packet IDs (protocol 340) ─────────────────────────

#[allow(dead_code)] // referenced for completeness; auto-emitted by server on teleport
const V112_C2S_TELEPORT_CONFIRM: u8 = 0x00;
const V112_C2S_TAB_COMPLETE: u8 = 0x01;
const V112_C2S_CHAT: u8 = 0x02;
const V112_C2S_CLIENT_STATUS: u8 = 0x03;
const V112_C2S_SETTINGS: u8 = 0x04;
const V112_C2S_CONFIRM_TRANSACTION: u8 = 0x05;
const V112_C2S_ENCHANT_ITEM: u8 = 0x06;
const V112_C2S_WINDOW_CLICK: u8 = 0x07;
const V112_C2S_CLOSE_WINDOW: u8 = 0x08;
const V112_C2S_PLUGIN_MESSAGE: u8 = 0x09;
const V112_C2S_USE_ENTITY: u8 = 0x0A;
const V112_C2S_KEEP_ALIVE: u8 = 0x0B;
const V112_C2S_PLAYER_POS: u8 = 0x0C;
const V112_C2S_PLAYER_POS_LOOK: u8 = 0x0D;
const V112_C2S_PLAYER_LOOK: u8 = 0x0E;
const V112_C2S_PLAYER_ON_GROUND: u8 = 0x0F;
const V112_C2S_PLAYER_ABILITIES: u8 = 0x12;
const V112_C2S_DIGGING: u8 = 0x13;
const V112_C2S_ENTITY_ACTION: u8 = 0x14;
const V112_C2S_STEER_VEHICLE: u8 = 0x15;
const V112_C2S_RESOURCE_PACK_STATUS: u8 = 0x18;
const V112_C2S_HELD_ITEM: u8 = 0x1A;
const V112_C2S_CREATIVE_INV: u8 = 0x1B;
const V112_C2S_UPDATE_SIGN: u8 = 0x1C;
const V112_C2S_ANIMATION: u8 = 0x1D;
const V112_C2S_SPECTATE: u8 = 0x1E;
const V112_C2S_BLOCK_PLACE: u8 = 0x1F;

/// Public entry point. Routes by server's epoch — only the 1.9–1.12 epoch
/// gets full conversion treatment; other modern epochs (1.13+/1.16+/...) fall
/// through to Passthrough, preserving previous behavior.
pub fn convert_c2s(payload: Bytes, server_proto: u32) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    let ver = nearest(server_proto);
    match ver.epoch() {
        Epoch::V1_9_To_1_12 => convert_c2s_to_1_12(id, body),
        // Other modern epochs are not the focus of this converter; leaving
        // them as Passthrough matches prior behavior.
        _ => convert_c2s_other_modern(id, body, ver),
    }
}

/// Conversion from 1.8 c2s to 1.9–1.12.2 c2s.
fn convert_c2s_to_1_12(id: u8, body: Bytes) -> ConversionResult {
    match id {
        V18_C2S_KEEP_ALIVE => c2s_keep_alive(body),
        V18_C2S_CHAT => c2s_chat_to_1_12(body),
        V18_C2S_USE_ENTITY => c2s_use_entity_to_1_12(body),
        V18_C2S_PLAYER_ON_GROUND => rewrap(body, V112_C2S_PLAYER_ON_GROUND),
        V18_C2S_PLAYER_POS => rewrap(body, V112_C2S_PLAYER_POS),
        V18_C2S_PLAYER_LOOK => rewrap(body, V112_C2S_PLAYER_LOOK),
        V18_C2S_PLAYER_POS_LOOK => rewrap(body, V112_C2S_PLAYER_POS_LOOK),
        V18_C2S_DIGGING => c2s_digging_to_1_12(body),
        V18_C2S_BLOCK_PLACE => c2s_block_place_to_1_12(body),
        V18_C2S_HELD_ITEM => rewrap(body, V112_C2S_HELD_ITEM),
        V18_C2S_ANIMATION => c2s_animation_to_1_12(),
        V18_C2S_ENTITY_ACTION => c2s_entity_action_to_1_12(body),
        V18_C2S_STEER_VEHICLE => rewrap(body, V112_C2S_STEER_VEHICLE),
        V18_C2S_CLOSE_WINDOW => rewrap(body, V112_C2S_CLOSE_WINDOW),
        V18_C2S_WINDOW_CLICK => rewrap(body, V112_C2S_WINDOW_CLICK),
        V18_C2S_CONFIRM_TRANSACTION => rewrap(body, V112_C2S_CONFIRM_TRANSACTION),
        V18_C2S_CREATIVE_INV => rewrap(body, V112_C2S_CREATIVE_INV),
        V18_C2S_ENCHANT_ITEM => rewrap(body, V112_C2S_ENCHANT_ITEM),
        V18_C2S_UPDATE_SIGN => c2s_update_sign_to_1_12(body),
        V18_C2S_PLAYER_ABILITIES => rewrap(body, V112_C2S_PLAYER_ABILITIES),
        V18_C2S_TAB_COMPLETE => c2s_tab_complete_to_1_12(body),
        V18_C2S_SETTINGS => c2s_settings_to_1_12(body),
        V18_C2S_CLIENT_STATUS => rewrap(body, V112_C2S_CLIENT_STATUS),
        V18_C2S_PLUGIN_MESSAGE => rewrap(body, V112_C2S_PLUGIN_MESSAGE),
        V18_C2S_SPECTATE => rewrap(body, V112_C2S_SPECTATE),
        V18_C2S_RESOURCE_PACK_STATUS => rewrap(body, V112_C2S_RESOURCE_PACK_STATUS),
        _ => ConversionResult::Passthrough,
    }
}

/// Best-effort conversion for newer modern epochs (1.13+). For now this just
/// preserves the old behavior — only a handful of packets have transforms
/// here and the rest are left as Passthrough. Tightening this is a follow-up.
fn convert_c2s_other_modern(id: u8, body: Bytes, ver: ProtocolVersion) -> ConversionResult {
    match id {
        V18_C2S_CHAT => c2s_chat_to_modern(body, ver),
        _ => ConversionResult::Passthrough,
    }
}

// ─── Per-packet body transforms ───────────────────────────────────────────

fn rewrap(body: Bytes, new_id: u8) -> ConversionResult {
    ConversionResult::Converted(vec![build_payload(new_id, &body)])
}

/// 1.8 KeepAlive sends a VarInt id. 1.12.2 expects a fixed 8-byte i64.
fn c2s_keep_alive(mut body: Bytes) -> ConversionResult {
    let Ok(VarInt(id)) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    out.put_i64(id as i64);
    ConversionResult::Converted(vec![build_payload(V112_C2S_KEEP_ALIVE, &out)])
}

/// 1.8 → 1.12.2: same body (a single String). Just rewrap with new id.
fn c2s_chat_to_1_12(mut body: Bytes) -> ConversionResult {
    let Ok(msg) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    msg.encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_C2S_CHAT, &out)])
}

/// Chat conversion for 1.13+ (used by the "other modern" path). Keeps the
/// previous heuristic of synthesizing a 1.19+ signed-chat envelope for
/// non-1.12.2 targets so we don't regress what was already partially wired up.
fn c2s_chat_to_modern(mut body: Bytes, _ver: ProtocolVersion) -> ConversionResult {
    let Ok(msg) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let mut out = BytesMut::new();
    msg.encode(&mut out).unwrap();
    out.put_i64(ts);
    out.put_i64(0);
    VarInt(0).encode(&mut out).unwrap();
    out.put_u8(0);
    // 0x05 is a rough heuristic across 1.19+ — exact id varies. This path is
    // best-effort and not the focus of this rewrite.
    ConversionResult::Converted(vec![build_payload(0x05, &out)])
}

/// 1.8 UseEntity:    VarInt target, VarInt type, [if type==2: f32 x, f32 y, f32 z]
/// 1.12.2 Interact:  VarInt target, VarInt type, [if type==2: f32 x, f32 y, f32 z],
///                   [if type∈{0,2}: VarInt hand]
/// We always append hand=0 (main hand) for Interact / InteractAt; Attack has
/// no hand field in either version.
fn c2s_use_entity_to_1_12(mut body: Bytes) -> ConversionResult {
    let Ok(VarInt(target)) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let Ok(VarInt(action)) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    VarInt(target).encode(&mut out).unwrap();
    VarInt(action).encode(&mut out).unwrap();
    match action {
        0 => {
            VarInt(0).encode(&mut out).unwrap(); // hand
        },
        1 => { /* attack: no extra */ },
        2 => {
            if body.remaining() < 12 {
                return ConversionResult::Passthrough;
            }
            out.put_f32(body.get_f32());
            out.put_f32(body.get_f32());
            out.put_f32(body.get_f32());
            VarInt(0).encode(&mut out).unwrap(); // hand
        },
        _ => return ConversionResult::Passthrough,
    }
    ConversionResult::Converted(vec![build_payload(V112_C2S_USE_ENTITY, &out)])
}

/// 1.8 PlayerDigging: u8 status, i32 x, u8 y, i32 z, i8 face
/// 1.12.2 PlayerAction: VarInt status, Position(u64) location, VarInt face
fn c2s_digging_to_1_12(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 + 4 + 1 + 4 + 1 {
        return ConversionResult::Passthrough;
    }
    let status = body.get_u8() as i32;
    let x = body.get_i32();
    let y = body.get_u8() as i32;
    let z = body.get_i32();
    let face = body.get_i8() as i32;
    let packed = pack_position(x, y, z);

    let mut out = BytesMut::new();
    VarInt(status).encode(&mut out).unwrap();
    out.put_i64(packed);
    VarInt(face).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_C2S_DIGGING, &out)])
}

/// 1.8 PlayerBlockPlacement:
///   i32 x, u8 y, i32 z, i8 direction, Slot held_item, u8 cx, u8 cy, u8 cz
/// 1.12.2 PlayerBlockPlacement:
///   Position location, VarInt face, VarInt hand, f32 cx, f32 cy, f32 cz
fn c2s_block_place_to_1_12(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 1 + 4 + 1 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32();
    let y = body.get_u8() as i32;
    let z = body.get_i32();
    let face = body.get_i8() as i32;

    // Special "use item" sentinel in 1.8 (-1 face, -1/-1/-1 coords with empty
    // slot) was used for snowball/bow etc. In 1.9+ this is a separate packet
    // (UseItem 0x20). We translate that case to a hand=0 UseItem.
    if face == -1 && x == -1 && z == -1 && (y as i8) == -1 {
        let mut out = BytesMut::new();
        VarInt(0).encode(&mut out).unwrap(); // hand = main
        return ConversionResult::Converted(vec![build_payload(0x20, &out)]);
    }

    // Consume the held-item slot — we don't need its contents for placement,
    // but we must advance the cursor past it so cx/cy/cz read correctly.
    if LegacySlot::decode(&mut body).is_err() {
        return ConversionResult::Passthrough;
    }
    if body.remaining() < 3 {
        return ConversionResult::Passthrough;
    }
    let cx = body.get_u8() as f32 / 16.0;
    let cy = body.get_u8() as f32 / 16.0;
    let cz = body.get_u8() as f32 / 16.0;

    let mut out = BytesMut::new();
    out.put_i64(pack_position(x, y, z));
    VarInt(face).encode(&mut out).unwrap();
    VarInt(0).encode(&mut out).unwrap(); // hand = main
    out.put_f32(cx);
    out.put_f32(cy);
    out.put_f32(cz);
    ConversionResult::Converted(vec![build_payload(V112_C2S_BLOCK_PLACE, &out)])
}

/// 1.8 Animation: empty body. 1.12.2 Animation: VarInt hand.
fn c2s_animation_to_1_12() -> ConversionResult {
    let mut out = BytesMut::new();
    VarInt(0).encode(&mut out).unwrap(); // hand = main
    ConversionResult::Converted(vec![build_payload(V112_C2S_ANIMATION, &out)])
}

/// 1.8 EntityAction: i32 entity_id, u8 action, i32 jump_boost
/// 1.12.2 EntityAction: VarInt entity_id, VarInt action, VarInt jump_boost
fn c2s_entity_action_to_1_12(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 1 + 4 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body.get_i32();
    let action = body.get_u8() as i32;
    let jump_boost = body.get_i32();

    let mut out = BytesMut::new();
    VarInt(entity_id).encode(&mut out).unwrap();
    VarInt(action).encode(&mut out).unwrap();
    VarInt(jump_boost).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_C2S_ENTITY_ACTION, &out)])
}

/// 1.8 UpdateSign: i32 x, i16 y, i32 z, 4× String lines (JSON chat)
/// 1.12.2 UpdateSign: Position location, 4× String lines (plain text)
fn c2s_update_sign_to_1_12(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 2 + 4 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32();
    let y = body.get_i16() as i32;
    let z = body.get_i32();
    let mut lines = [String::new(), String::new(), String::new(), String::new()];
    for line in lines.iter_mut() {
        let Ok(s) = String::decode(&mut body) else {
            return ConversionResult::Passthrough;
        };
        *line = s;
    }

    let mut out = BytesMut::new();
    out.put_i64(pack_position(x, y, z));
    for line in &lines {
        line.encode(&mut out).unwrap();
    }
    ConversionResult::Converted(vec![build_payload(V112_C2S_UPDATE_SIGN, &out)])
}

/// 1.8 TabComplete: String text, [bool has_pos, i64 looked_at_position]
/// 1.12.2 TabComplete: String text, bool assume_command, [bool has_pos, Position]
fn c2s_tab_complete_to_1_12(mut body: Bytes) -> ConversionResult {
    let Ok(text) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let has_pos = if body.remaining() >= 1 {
        body.get_u8() != 0
    } else {
        false
    };
    let pos = if has_pos && body.remaining() >= 8 {
        Some(body.get_i64())
    } else {
        None
    };

    let assume_command = text.starts_with('/');
    let mut out = BytesMut::new();
    text.encode(&mut out).unwrap();
    out.put_u8(assume_command as u8);
    out.put_u8(has_pos as u8);
    if let Some(p) = pos {
        out.put_i64(p);
    }
    ConversionResult::Converted(vec![build_payload(V112_C2S_TAB_COMPLETE, &out)])
}

/// 1.8 ClientSettings: String locale, i8 view_distance, i8 chat_mode,
///                    bool chat_colors, u8 displayed_skin_parts
/// 1.12.2 ClientSettings: same as above (chat_mode is a VarInt but values
///                    0/1/2 are one byte, so wire-identical) plus a trailing
///                    VarInt main_hand. We append main_hand=1 (right).
fn c2s_settings_to_1_12(body: Bytes) -> ConversionResult {
    let mut out = BytesMut::from(body.as_ref());
    VarInt(1).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_C2S_SETTINGS, &out)])
}

/// Pack (x, y, z) into the 1.8–1.13 (LEGACY) Mojang Position layout:
/// x in bits 38–63, y in bits 26–37, z in bits 0–25. Mojang moved Y
/// to the low 12 bits at 1.14 (`encode_modern_position`) — all three
/// call sites here target 1.12.2 (proto 340), so legacy layout is
/// what the server actually decodes.
///
/// The prior comment + formula here claimed the layout was unchanged
/// since 1.8 and used the 1.14+ packing, producing 1.12.2 packets with
/// Y and Z bits crossed. Verified against
/// `kojacoord_protocol::types::encode_legacy_position` (canonical
/// legacy packer) and minecraft.wiki Data_types §Position which notes
/// "the position type was different before 1.14".
fn pack_position(x: i32, y: i32, z: i32) -> i64 {
    kojacoord_protocol::types::encode_legacy_position(kojacoord_protocol::types::Position {
        x,
        y,
        z,
    })
}

// ──────────────────────────────────────────────────────────────────────────
// S2C: 1.8 server (or proxy-emitted "v1_8") → 1.12.2 client
// ──────────────────────────────────────────────────────────────────────────
//
// This is the forward direction companion to `modern_to_v1_8`, enabling the
// 1.7.10 → 1.8 → 1.12.2 two-hop S2C pipeline.
//
// ── Clientbound (server → client) packet-id mapping table ────────────────
//   name                        1.8     1.12.2   field xform?
//   KeepAlive                   0x00    0x1F     VarInt → i64
//   JoinGame                    0x01    0x23     i8 dim → i32 dim; add reduced_debug
//   ChatMessage                 0x02    0x0F     none
//   TimeUpdate                  0x03    0x47     none
//   EntityEquipment             0x04    0x3F     none
//   SpawnPosition               0x05    0x46     none
//   UpdateHealth                0x06    0x41     none
//   Respawn                     0x07    0x35     none (both i32 dimension)
//   PlayerPosLook               0x08    0x2F     append VarInt teleport_id
//   HeldItemChange              0x09    0x3A     none
//   UseBed                      0x0A    0x30     none
//   Animation                   0x0B    0x06     none
//   SpawnPlayer                 0x0C    0x05     none
//   CollectItem                  0x0D    0x4B     append VarInt count (1)
//   SpawnObject                 0x0E    0x00     none
//   SpawnMob                    0x0F    0x03     none
//   SpawnPainting               0x10    0x04     none
//   SpawnExpOrb                  0x11    0x01     none
//   EntityVelocity              0x12    0x3E     none
//   DestroyEntities             0x13    0x32     none
//   Entity                      0x14    0x28     none
//   EntityRelMove               0x15    0x25     i8 deltas → i16 (*128); add onGround
//   EntityLook                  0x16    0x27     add onGround
//   EntityLookRelMove           0x17    0x26     i8 deltas → i16 (*128); add onGround
//   EntityTeleport              0x18    0x4C     i32 fixed-point → f64 (/32)
//   EntityHeadLook              0x19    0x36     none
//   EntityStatus                0x1A    0x1B     none
//   AttachEntity                0x1B    0x3D     none
//   EntityMetadata              0x1C    0x3C     none (best-effort)
//   EntityEffect                0x1D    0x4F     none
//   RemoveEntityEffect          0x1E    0x33     none
//   SetExperience               0x1F    0x40     none
//   EntityProperties             0x20    0x4E     none
//   ChunkData                   0x21    0x20     none
//   MultiBlockChange            0x22    0x10     none
//   BlockChange                 0x23    0x0B     separate coords+id+meta → Position+blockState
//   BlockAction                 0x24    0x0A     none (1.8 uses packed Position already)
//   BlockBreakAnim              0x25    0x08     none (1.8 uses packed Position)
//   Explosion                  0x27    0x1C     none
//   Effect                      0x28    0x21     none
//   SoundEffect                 0x29    0x49     none
//   Particle                    0x2A    0x22     none
//   ChangeGameState             0x2B    0x1E     none
//   SpawnGlobalEntity           0x2C    0x02     none
//   OpenWindow                  0x2D    0x13     none
//   CloseWindow                 0x2E    0x12     none
//   SetSlot                     0x2F    0x16     none
//   WindowItems                 0x30    0x14     none
//   WindowProperty              0x31    0x15     none
//   ConfirmTransaction          0x32    0x11     none
//   UpdateSign                  0x33    none     drop (1.8→1.12 signs go via UpdateTileEntity)
//   Map                         0x34    0x24     none
//   UpdateTileEntity            0x35    0x09     none
//   OpenSignEditor              0x36    0x2A     none
//   Statistics                  0x37    0x07     none
//   PlayerListItem              0x38    0x2E     none
//   PlayerAbilities             0x39    0x2C     none
//   TabComplete                 0x3A    0x0E     none
//   ScoreboardObjective         0x3B    0x42     none
//   UpdateScore                 0x3C    0x45     none
//   DisplayScoreboard           0x3D    0x3B     none
//   Teams                       0x3E    0x44     none
//   PluginMessage               0x3F    0x18     none
//   Disconnect                  0x40    0x1A     none
//   ServerDifficulty            0x41    0x0D     none
//   CombatEvent                 0x42    0x2D     none
//   Camera                      0x43    0x39     none
//   WorldBorder                 0x44    0x38     none
//   Title                       0x45    0x48     none

const V18_S2C_S2C_KEEP_ALIVE: u8 = 0x00;
const V18_S2C_JOIN_GAME: u8 = 0x01;
const V18_S2C_CHAT: u8 = 0x02;
const V18_S2C_TIME_UPDATE: u8 = 0x03;
const V18_S2C_ENTITY_EQUIPMENT: u8 = 0x04;
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
const V18_S2C_DESTROY_ENTITIES: u8 = 0x13;
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
const V18_S2C_SET_EXPERIENCE: u8 = 0x1F;
const V18_S2C_ENTITY_PROPERTIES: u8 = 0x20;
const V18_S2C_CHUNK_DATA: u8 = 0x21;
const V18_S2C_MULTI_BLOCK_CHANGE: u8 = 0x22;
const V18_S2C_BLOCK_CHANGE: u8 = 0x23;
const V18_S2C_BLOCK_ACTION: u8 = 0x24;
const V18_S2C_BLOCK_BREAK_ANIM: u8 = 0x25;
const V18_S2C_EXPLOSION: u8 = 0x27;
const V18_S2C_EFFECT: u8 = 0x28;
const V18_S2C_SOUND_EFFECT: u8 = 0x29;
const V18_S2C_PARTICLE: u8 = 0x2A;
const V18_S2C_CHANGE_GAME_STATE: u8 = 0x2B;
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
const V18_S2C_PLAYER_ABILITIES: u8 = 0x39;
const V18_S2C_TAB_COMPLETE: u8 = 0x3A;
const V18_S2C_SCOREBOARD_OBJ: u8 = 0x3B;
const V18_S2C_UPDATE_SCORE: u8 = 0x3C;
const V18_S2C_DISPLAY_SCOREBOARD: u8 = 0x3D;
const V18_S2C_TEAMS: u8 = 0x3E;
const V18_S2C_PLUGIN_MESSAGE: u8 = 0x3F;
const V18_S2C_DISCONNECT: u8 = 0x40;
const V18_S2C_SERVER_DIFFICULTY: u8 = 0x41;
const V18_S2C_COMBAT_EVENT: u8 = 0x42;
const V18_S2C_CAMERA: u8 = 0x43;
const V18_S2C_WORLD_BORDER: u8 = 0x44;
const V18_S2C_TITLE: u8 = 0x45;
const V18_S2C_PLAYER_LIST_HEADER_FOOTER: u8 = 0x47;
const V18_S2C_RESOURCE_PACK: u8 = 0x48;

const V112_S2C_KEEP_ALIVE: u8 = 0x1F;
const V112_S2C_JOIN_GAME: u8 = 0x23;
const V112_S2C_SPAWN_POSITION: u8 = 0x46;
const V112_S2C_PLAYER_POS_LOOK: u8 = 0x2F;
const V112_S2C_COLLECT_ITEM: u8 = 0x4B;
const V112_S2C_ENTITY_REL_MOVE: u8 = 0x25;
const V112_S2C_ENTITY_LOOK: u8 = 0x27;
const V112_S2C_ENTITY_LOOK_REL_MOVE: u8 = 0x26;
const V112_S2C_ENTITY_TELEPORT: u8 = 0x4C;
const V112_S2C_BLOCK_CHANGE: u8 = 0x0B;

pub fn convert_s2c(payload: Bytes, server_proto: u32) -> ConversionResult {
    let ver = nearest(server_proto);
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    match ver.epoch() {
        Epoch::V1_9_To_1_12 => convert_s2c_to_1_12(id, body),
        _ => ConversionResult::Passthrough,
    }
}

fn convert_s2c_to_1_12(id: u8, body: Bytes) -> ConversionResult {
    match id {
        // Packets that need field-level conversion
        V18_S2C_S2C_KEEP_ALIVE => s2c_keep_alive(body),
        V18_S2C_JOIN_GAME => s2c_join_game(body),
        V18_S2C_PLAYER_POS_LOOK => s2c_player_pos_look(body),
        V18_S2C_COLLECT_ITEM => s2c_collect_item(body),
        V18_S2C_ENTITY_REL_MOVE => s2c_entity_rel_move(body, false),
        V18_S2C_ENTITY_LOOK => s2c_entity_look(body),
        V18_S2C_ENTITY_LOOK_REL_MOVE => s2c_entity_rel_move(body, true),
        V18_S2C_ENTITY_TELEPORT => s2c_entity_teleport(body),
        V18_S2C_BLOCK_CHANGE => s2c_block_change(body),
        V18_S2C_CHAT => rewrap(body, 0x0F),
        V18_S2C_RESPAWN => s2c_respawn(body),

        // Body-identical, just ID remap (per the mapping table in module doc)
        V18_S2C_TIME_UPDATE => rewrap(body, 0x47),
        V18_S2C_ENTITY_EQUIPMENT => rewrap(body, 0x3F),
        V18_S2C_SPAWN_POSITION => rewrap(body, 0x46),
        V18_S2C_UPDATE_HEALTH => rewrap(body, 0x41),
        V18_S2C_HELD_ITEM_CHANGE => rewrap(body, 0x3A),
        V18_S2C_USE_BED => rewrap(body, 0x30),
        V18_S2C_ANIMATION => rewrap(body, 0x06),
        V18_S2C_SPAWN_PLAYER => rewrap(body, 0x05),
        V18_S2C_SPAWN_OBJECT => rewrap(body, 0x00),
        V18_S2C_SPAWN_MOB => rewrap(body, 0x03),
        V18_S2C_SPAWN_PAINTING => rewrap(body, 0x04),
        V18_S2C_SPAWN_EXP_ORB => rewrap(body, 0x01),
        V18_S2C_ENTITY_VELOCITY => rewrap(body, 0x3E),
        V18_S2C_DESTROY_ENTITIES => rewrap(body, 0x32),
        V18_S2C_ENTITY => rewrap(body, 0x28),
        V18_S2C_ENTITY_HEAD_LOOK => rewrap(body, 0x36),
        V18_S2C_ENTITY_STATUS => rewrap(body, 0x1B),
        V18_S2C_ATTACH_ENTITY => rewrap(body, 0x3D),
        V18_S2C_ENTITY_METADATA => rewrap(body, 0x3C),
        V18_S2C_ENTITY_EFFECT => rewrap(body, 0x4F),
        V18_S2C_REMOVE_ENTITY_EFFECT => rewrap(body, 0x33),
        V18_S2C_SET_EXPERIENCE => rewrap(body, 0x40),
        V18_S2C_ENTITY_PROPERTIES => rewrap(body, 0x4E),
        V18_S2C_CHUNK_DATA => rewrap(body, 0x20),
        V18_S2C_MULTI_BLOCK_CHANGE => rewrap(body, 0x10),
        V18_S2C_BLOCK_ACTION => rewrap(body, 0x0A),
        V18_S2C_BLOCK_BREAK_ANIM => rewrap(body, 0x08),
        V18_S2C_UPDATE_TILE_ENTITY => rewrap(body, 0x09),
        V18_S2C_EXPLOSION => rewrap(body, 0x1C),
        V18_S2C_EFFECT => rewrap(body, 0x21),
        V18_S2C_SOUND_EFFECT => rewrap(body, 0x49),
        V18_S2C_PARTICLE => rewrap(body, 0x22),
        V18_S2C_CHANGE_GAME_STATE => rewrap(body, 0x1E),
        V18_S2C_SPAWN_GLOBAL => rewrap(body, 0x02),
        V18_S2C_OPEN_WINDOW => rewrap(body, 0x13),
        V18_S2C_CLOSE_WINDOW => rewrap(body, 0x12),
        V18_S2C_SET_SLOT => rewrap(body, 0x16),
        V18_S2C_WINDOW_ITEMS => rewrap(body, 0x14),
        V18_S2C_WINDOW_PROPERTY => rewrap(body, 0x15),
        V18_S2C_CONFIRM_TRANSACTION => rewrap(body, 0x11),
        V18_S2C_OPEN_SIGN_EDITOR => rewrap(body, 0x2A),
        V18_S2C_STATISTICS => rewrap(body, 0x07),
        V18_S2C_PLAYER_LIST_ITEM => rewrap(body, 0x2E),
        V18_S2C_PLAYER_ABILITIES => rewrap(body, 0x2C),
        V18_S2C_TAB_COMPLETE => rewrap(body, 0x0E),
        V18_S2C_SCOREBOARD_OBJ => rewrap(body, 0x42),
        V18_S2C_UPDATE_SCORE => rewrap(body, 0x45),
        V18_S2C_DISPLAY_SCOREBOARD => rewrap(body, 0x3B),
        V18_S2C_TEAMS => rewrap(body, 0x44),
        V18_S2C_PLUGIN_MESSAGE => rewrap(body, 0x18),
        V18_S2C_DISCONNECT => rewrap(body, 0x1A),
        V18_S2C_SERVER_DIFFICULTY => rewrap(body, 0x0D),
        V18_S2C_COMBAT_EVENT => rewrap(body, 0x2D),
        V18_S2C_CAMERA => rewrap(body, 0x39),
        V18_S2C_WORLD_BORDER => rewrap(body, 0x38),
        V18_S2C_TITLE => rewrap(body, 0x48),
        V18_S2C_PLAYER_LIST_HEADER_FOOTER => rewrap(body, 0x4A),
        V18_S2C_RESOURCE_PACK => rewrap(body, 0x34),

        // Packets with no 1.12.2 equivalent or too different
        V18_S2C_UPDATE_SIGN => {
            // 1.8 UpdateSign → 1.12.2 uses UpdateTileEntity for signs instead
            ConversionResult::Drop
        },
        V18_S2C_MAP => rewrap(body, 0x24),

        _ => ConversionResult::Passthrough,
    }
}

fn s2c_keep_alive(mut body: Bytes) -> ConversionResult {
    // 1.8: VarInt keepAliveId. 1.12.2: i64 keepAliveId.
    let Ok(VarInt(id)) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    out.put_i64(id as i64);
    ConversionResult::Converted(vec![build_payload(V112_S2C_KEEP_ALIVE, &out)])
}

fn s2c_join_game(body: Bytes) -> ConversionResult {
    // 1.8: i32 eid; u8 gamemode; i8 dimension; u8 difficulty; u8 maxPlayers; string levelType; bool reducedDebug.
    // 1.12.2: i32 eid; u8 gamemode; i32 dimension; u8 difficulty; u8 maxPlayers; string levelType; bool reducedDebug.
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.i32() else {
        return ConversionResult::Passthrough;
    };
    let Some(gm) = r.u8() else {
        return ConversionResult::Passthrough;
    };
    let dimension = r.i8().unwrap_or(0) as i32;
    let difficulty = r.u8().unwrap_or(2);
    let max_players = r.u8().unwrap_or(100);
    let level_type = r.string().unwrap_or_else(|| "default".to_owned());
    let reduced_debug = r.u8().unwrap_or(0);

    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_u8(gm);
    out.put_i32(dimension);
    out.put_u8(difficulty);
    out.put_u8(max_players);
    level_type.encode(&mut out).unwrap();
    out.put_u8(reduced_debug);
    ConversionResult::Converted(vec![build_payload(V112_S2C_JOIN_GAME, &out)])
}

fn s2c_player_pos_look(body: Bytes) -> ConversionResult {
    // 1.8: 3×f64, 2×f32, u8 flags. 1.12.2: same + VarInt teleport_id.
    let mut r = super::safe::Reader::new(body);
    let Some(x) = r.f64() else {
        return ConversionResult::Passthrough;
    };
    let Some(y) = r.f64() else {
        return ConversionResult::Passthrough;
    };
    let Some(z) = r.f64() else {
        return ConversionResult::Passthrough;
    };
    let Some(yaw) = r.f32() else {
        return ConversionResult::Passthrough;
    };
    let Some(pitch) = r.f32() else {
        return ConversionResult::Passthrough;
    };
    let flags = r.u8().unwrap_or(0);

    let mut out = BytesMut::new();
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_f32(yaw);
    out.put_f32(pitch);
    out.put_u8(flags);
    VarInt(0).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_S2C_PLAYER_POS_LOOK, &out)])
}

fn s2c_collect_item(body: Bytes) -> ConversionResult {
    // 1.8: VarInt collected, VarInt collector. 1.12.2: same + VarInt count.
    let mut r = super::safe::Reader::new(body);
    let Some(collected) = r.varint() else {
        return ConversionResult::Passthrough;
    };
    let Some(collector) = r.varint() else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    VarInt(collected).encode(&mut out).unwrap();
    VarInt(collector).encode(&mut out).unwrap();
    VarInt(1).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_S2C_COLLECT_ITEM, &out)])
}

fn s2c_entity_rel_move(body: Bytes, has_look: bool) -> ConversionResult {
    // 1.8: VarInt eid; i8 dx/dy/dz; [if has_look: u8 yaw, u8 pitch]; bool onGround.
    // 1.12.2: VarInt eid; i16 dx/dy/dz (*128); [if has_look: u8 yaw, u8 pitch]; bool onGround.
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else {
        return ConversionResult::Passthrough;
    };
    let Some(dx_8) = r.i8() else {
        return ConversionResult::Passthrough;
    };
    let Some(dy_8) = r.i8() else {
        return ConversionResult::Passthrough;
    };
    let Some(dz_8) = r.i8() else {
        return ConversionResult::Passthrough;
    };
    let look = if has_look {
        let yaw = r.u8().unwrap_or(0);
        let pitch = r.u8().unwrap_or(0);
        Some((yaw, pitch))
    } else {
        None
    };
    let on_ground = r.u8().unwrap_or(1);

    let dx_16 = (dx_8 as i16).wrapping_mul(128);
    let dy_16 = (dy_8 as i16).wrapping_mul(128);
    let dz_16 = (dz_8 as i16).wrapping_mul(128);

    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_i16(dx_16);
    out.put_i16(dy_16);
    out.put_i16(dz_16);
    let new_id = if let Some((yaw, pitch)) = look {
        out.put_u8(yaw);
        out.put_u8(pitch);
        V112_S2C_ENTITY_LOOK_REL_MOVE
    } else {
        V112_S2C_ENTITY_REL_MOVE
    };
    out.put_u8(on_ground);
    ConversionResult::Converted(vec![build_payload(new_id, &out)])
}

fn s2c_entity_look(body: Bytes) -> ConversionResult {
    // 1.8: VarInt eid; u8 yaw; u8 pitch; bool onGround. 1.12.2: same shape.
    // Just rewrap with the 1.12.2 packet id.
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_LOOK, &body)])
}

fn s2c_entity_teleport(body: Bytes) -> ConversionResult {
    // 1.8: VarInt eid; i32 x; i32 y; i32 z; u8 yaw; u8 pitch; bool onGround.
    // 1.12.2: VarInt eid; f64 x; f64 y; f64 z; u8 yaw; u8 pitch; bool onGround.
    // 1.8 uses fixed-point coords (block*32); 1.12.2 uses f64 absolute.
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
    let yaw = r.u8().unwrap_or(0);
    let pitch = r.u8().unwrap_or(0);
    let on_ground = r.u8().unwrap_or(1);

    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_f64(x as f64 / 32.0);
    out.put_f64(y as f64 / 32.0);
    out.put_f64(z as f64 / 32.0);
    out.put_u8(yaw);
    out.put_u8(pitch);
    out.put_u8(on_ground);
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_TELEPORT, &out)])
}

fn s2c_block_change(body: Bytes) -> ConversionResult {
    // 1.8 (when coming from v1_7_to_v1_8 converter): i32 x; u8 y; i32 z; VarInt block_id; u8 metadata.
    // 1.12.2: Position packed; VarInt block_state (= block_id << 4 | meta).
    //
    // NOTE: The internal "v1_8" BlockChange produced by v1_7_to_v1_8 retains
    // 1.7-style separate-int coordinates (not packed Position). However, a
    // *real* 1.8 server sends packed Position. We detect which format by
    // checking body size: separate-int is 4+1+4+varint+1 ≈ 11 bytes;
    // packed-long is 8+varint ≈ 9 bytes.
    //
    // Since we can't reliably distinguish, we check if the body starts with
    // something that looks like a valid packed Position. A simpler approach:
    // the dispatch in mod.rs will only route 1.7→1.12 through this path, so
    // the BlockChange bodies here always come from v1_7_to_v1_8 which uses
    // separate-int format.
    let mut r = super::safe::Reader::new(body);
    let Some(x) = r.i32() else {
        return ConversionResult::Passthrough;
    };
    let Some(y) = r.u8() else {
        return ConversionResult::Passthrough;
    };
    let Some(z) = r.i32() else {
        return ConversionResult::Passthrough;
    };
    let Some(block_id) = r.varint() else {
        return ConversionResult::Passthrough;
    };
    let metadata = r.u8().unwrap_or(0);
    let block_state = (block_id << 4) | (metadata as i32 & 0xF);

    let packed = pack_position(x, y as i32, z);
    let mut out = BytesMut::new();
    out.put_i64(packed);
    VarInt(block_state).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_S2C_BLOCK_CHANGE, &out)])
}

fn s2c_respawn(body: Bytes) -> ConversionResult {
    // 1.8: i32 dimension; u8 difficulty; u8 gamemode; String levelType.
    // 1.12.2: i32 dimension; u8 difficulty; u8 gamemode; String levelType.
    // Body is identical between 1.8 and 1.12.2 — just rewrap with 1.12.2 id.
    ConversionResult::Converted(vec![build_payload(0x35, &body)])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert(id: u8, body: &[u8], proto: u32) -> Option<(u8, Bytes)> {
        let mut full = BytesMut::new();
        VarInt(id as i32).encode(&mut full).unwrap();
        full.extend_from_slice(body);
        match convert_c2s(full.freeze(), proto) {
            ConversionResult::Converted(mut pkts) if pkts.len() == 1 => {
                let mut p = pkts.remove(0);
                let new_id = VarInt::decode(&mut p).ok()?.0 as u8;
                Some((new_id, p))
            },
            _ => None,
        }
    }

    #[test]
    fn keep_alive_varint_to_long() {
        let mut body = BytesMut::new();
        VarInt(0x1234).encode(&mut body).unwrap();
        let (id, rest) = convert(V18_C2S_KEEP_ALIVE, &body, 340).unwrap();
        assert_eq!(id, V112_C2S_KEEP_ALIVE);
        let mut r = rest;
        assert_eq!(r.get_i64(), 0x1234);
    }

    #[test]
    fn chat_rewrap() {
        let mut body = BytesMut::new();
        "hello".to_owned().encode(&mut body).unwrap();
        let (id, mut rest) = convert(V18_C2S_CHAT, &body, 340).unwrap();
        assert_eq!(id, V112_C2S_CHAT);
        assert_eq!(String::decode(&mut rest).unwrap(), "hello");
    }

    #[test]
    fn use_entity_attack_no_hand() {
        let mut body = BytesMut::new();
        VarInt(42).encode(&mut body).unwrap();
        VarInt(1).encode(&mut body).unwrap(); // attack
        let (id, mut rest) = convert(V18_C2S_USE_ENTITY, &body, 340).unwrap();
        assert_eq!(id, V112_C2S_USE_ENTITY);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 42);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 1);
        assert!(rest.is_empty()); // no hand field for attack
    }

    #[test]
    fn use_entity_interact_appends_hand() {
        let mut body = BytesMut::new();
        VarInt(7).encode(&mut body).unwrap();
        VarInt(0).encode(&mut body).unwrap(); // interact
        let (id, mut rest) = convert(V18_C2S_USE_ENTITY, &body, 340).unwrap();
        assert_eq!(id, V112_C2S_USE_ENTITY);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 7);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 0);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 0); // hand=main
    }

    #[test]
    fn animation_gets_hand() {
        let (id, mut rest) = convert(V18_C2S_ANIMATION, &[], 340).unwrap();
        assert_eq!(id, V112_C2S_ANIMATION);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 0);
    }

    #[test]
    fn entity_action_widens_to_varint() {
        let mut body = BytesMut::new();
        body.put_i32(99);
        body.put_u8(3); // sneaking
        body.put_i32(0);
        let (id, mut rest) = convert(V18_C2S_ENTITY_ACTION, &body, 340).unwrap();
        assert_eq!(id, V112_C2S_ENTITY_ACTION);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 99);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 3);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 0);
    }

    #[test]
    fn digging_packs_position() {
        let mut body = BytesMut::new();
        body.put_u8(0); // start digging
        body.put_i32(10);
        body.put_u8(64);
        body.put_i32(-20);
        body.put_i8(1); // face
        let (id, mut rest) = convert(V18_C2S_DIGGING, &body, 340).unwrap();
        assert_eq!(id, V112_C2S_DIGGING);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 0);
        let pos = rest.get_i64();
        let want = pack_position(10, 64, -20);
        assert_eq!(pos, want);
        assert_eq!(VarInt::decode(&mut rest).unwrap().0, 1);
    }

    #[test]
    fn settings_appends_main_hand() {
        let mut body = BytesMut::new();
        "en_US".to_owned().encode(&mut body).unwrap();
        body.put_i8(8); // view distance
        body.put_i8(0); // chat mode
        body.put_u8(1); // chat colors
        body.put_u8(0x7F); // displayed skin parts
        let (id, rest) = convert(V18_C2S_SETTINGS, &body, 340).unwrap();
        assert_eq!(id, V112_C2S_SETTINGS);
        let last = rest[rest.len() - 1];
        assert_eq!(last, 1); // VarInt(1) main_hand
    }

    #[test]
    fn other_packets_passthrough_outside_epoch() {
        let mut body = BytesMut::new();
        VarInt(123).encode(&mut body).unwrap();
        let mut full = BytesMut::new();
        VarInt(V18_C2S_KEEP_ALIVE as i32).encode(&mut full).unwrap();
        full.extend_from_slice(&body);
        // proto 754 = 1.16.5 — outside V1_9_To_1_12 epoch.
        match convert_c2s(full.freeze(), 754) {
            ConversionResult::Passthrough => {},
            _ => panic!("expected passthrough for non-1.12 epoch"),
        }
    }
}
