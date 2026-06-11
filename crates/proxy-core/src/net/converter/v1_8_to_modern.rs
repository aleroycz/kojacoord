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
