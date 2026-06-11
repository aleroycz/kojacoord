//! Reverse of `v1_6_4_to_v1_12_2.rs`: convert client-to-server (c2s)
//! packets from a 1.12.2 (or composition-folded modern) client into
//! the pre-netty 1.6.4 wire format a Notchian 1.6.4 server expects.
//!
//! Scope: minimal coverage of the packets a stock vanilla 1.12.2
//! client emits in steady state — enough to keep the connection
//! alive and let the player chat. Anything else (block placement,
//! digging, entity interactions) falls through to `Passthrough` —
//! the 1.6.4 server will ignore the malformed payload but the
//! connection itself survives.
//!
//! Authoritative sources used:
//!   * MCP-doc class-name convention `Packet<N><Name>` for 1.6.4
//!     pre-netty packet ids (`Packet0KeepAlive`, `Packet3Chat`).
//!   * `kojacoord_protocol::versions::v1_6_x::play::{encode_legacy_string,
//!     ClientboundKeepAlive}` for the wire shape (UCS-2 BE strings,
//!     i32 KeepAlive id).
//!   * `kojacoord_protocol::versions::v1_12_x::play::ClientboundKeepAlive`
//!     for the 1.12.2 (proto 340) wire shape (i64 KeepAlive id —
//!     Mojang switched from VarInt to Long at proto 340).
//!
//! Wire-direction reminder: c2s = client → server. SOURCE is 1.12.2
//! client, TARGET is 1.6.4 server.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use kojacoord_protocol::codec::Decode;
#[cfg(test)]
use kojacoord_protocol::codec::Encode;
use kojacoord_protocol::types::VarInt;

use super::{build_payload, split_id};
use crate::converter::ConversionResult;

// ---- 1.12.2 source ids (per registry proto 340 / BungeeCord
// `Protocol.java::TO_SERVER`) ----
const V112_C2S_TELEPORT_CONFIRM: u8 = 0x00;
const V112_C2S_CHAT: u8 = 0x02;
const V112_C2S_CLIENT_STATUS: u8 = 0x03;
const V112_C2S_CLIENT_SETTINGS: u8 = 0x04;
const V112_C2S_CLOSE_WINDOW: u8 = 0x08;
const V112_C2S_PLUGIN_MESSAGE: u8 = 0x09;
const V112_C2S_USE_ENTITY: u8 = 0x0A;
const V112_C2S_KEEP_ALIVE: u8 = 0x0B;
const V112_C2S_MOVE_PLAYER_POS: u8 = 0x0C;
const V112_C2S_PLAYER_POS_LOOK: u8 = 0x0E;
const V112_C2S_MOVE_PLAYER_ROT: u8 = 0x0F;
const V112_C2S_PLAYER_ABILITIES: u8 = 0x13;
const V112_C2S_PLAYER_DIGGING: u8 = 0x14;
const V112_C2S_ENTITY_ACTION: u8 = 0x15;
const V112_C2S_HELD_ITEM_CHANGE: u8 = 0x1A;
const V112_C2S_UPDATE_SIGN: u8 = 0x1C;
const V112_C2S_ANIMATION: u8 = 0x1D;
const V112_C2S_PLAYER_BLOCK_PLACEMENT: u8 = 0x1F;
const V112_C2S_USE_ITEM: u8 = 0x20;

// ---- 1.6.4 target ids (MCP-doc, decimal = hex) ----
const V164_C2S_KEEP_ALIVE: u8 = 0x00; // Packet0KeepAlive
const V164_C2S_CHAT: u8 = 0x03; // Packet3Chat
const V164_C2S_USE_ENTITY: u8 = 0x07; // Packet7UseEntity
/// Pre-netty c2s "still alive" packet. Not currently produced by our
/// modern→pre-netty converter (modern clients don't emit a bare
/// on-ground update either), but kept as documentation of the
/// authentic 1.6.4 packet table per HexaCord.
#[allow(dead_code)]
const V164_C2S_PLAYER_ON_GROUND: u8 = 0x0A; // Packet10Flying
const V164_C2S_MOVE_PLAYER_POS: u8 = 0x0B; // Packet11PlayerPosition
const V164_C2S_MOVE_PLAYER_ROT: u8 = 0x0C; // Packet12PlayerLook
const V164_C2S_PLAYER_POS_LOOK: u8 = 0x0D; // Packet13PlayerLookMove
const V164_C2S_PLAYER_DIGGING: u8 = 0x0E; // Packet14BlockDig
const V164_C2S_PLAYER_BLOCK_PLACEMENT: u8 = 0x0F; // Packet15Place
const V164_C2S_HELD_ITEM_CHANGE: u8 = 0x10; // Packet16BlockItemSwitch
const V164_C2S_ANIMATION: u8 = 0x12; // Packet18Animation
const V164_C2S_ENTITY_ACTION: u8 = 0x13; // Packet19EntityAction
const V164_C2S_CLIENT_COMMAND: u8 = 0x16; // Packet22ClientCommand (respawn)
const V164_C2S_CLOSE_WINDOW: u8 = 0x65; // Packet101CloseWindow
const V164_C2S_UPDATE_SIGN: u8 = 0x82; // Packet130UpdateSign
const V164_C2S_PLAYER_ABILITIES: u8 = 0xCA; // PacketCAPlayerAbilities
const V164_C2S_CLIENT_SETTINGS: u8 = 0xCC; // PacketCCSettings
const V164_C2S_PLUGIN_MESSAGE: u8 = 0xFA; // PacketFAPluginMessage

pub fn convert_c2s(payload: Bytes) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };
    match id {
        // TeleportConfirm: 1.6.4 has no equivalent. Drop silently.
        V112_C2S_TELEPORT_CONFIRM => ConversionResult::Drop,
        V112_C2S_KEEP_ALIVE => c2s_keep_alive(body),
        V112_C2S_CHAT => c2s_chat(body),
        V112_C2S_CLIENT_STATUS => c2s_client_status(body),
        V112_C2S_CLIENT_SETTINGS => c2s_client_settings(body),
        V112_C2S_CLOSE_WINDOW => c2s_close_window(body),
        V112_C2S_PLUGIN_MESSAGE => c2s_plugin_message(body),
        V112_C2S_USE_ENTITY => c2s_use_entity(body),
        V112_C2S_MOVE_PLAYER_POS => c2s_move_player_pos(body),
        V112_C2S_PLAYER_POS_LOOK => c2s_player_pos_look(body),
        V112_C2S_MOVE_PLAYER_ROT => c2s_move_player_rot(body),
        V112_C2S_PLAYER_ABILITIES => c2s_player_abilities(body),
        V112_C2S_PLAYER_DIGGING => c2s_player_digging(body),
        V112_C2S_ENTITY_ACTION => c2s_entity_action(body),
        V112_C2S_HELD_ITEM_CHANGE => c2s_held_item_change(body),
        V112_C2S_UPDATE_SIGN => c2s_update_sign(body),
        V112_C2S_ANIMATION => c2s_animation(body),
        V112_C2S_PLAYER_BLOCK_PLACEMENT => c2s_player_block_placement(body),
        // UseItem: 1.12.2 split block-place from item-use. 1.6.4 has no
        // separate UseItem packet; the block-placement packet covered
        // right-click-air via face=-1. Drop the standalone form.
        V112_C2S_USE_ITEM => ConversionResult::Drop,
        _ => ConversionResult::Passthrough,
    }
}

/// 1.12.2 KeepAlive c2s: i64 id (Mojang switched to Long at proto 340).
/// 1.6.4 KeepAlive c2s: i32 id.
fn c2s_keep_alive(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let id_i64 = body.get_i64();
    // 1.12.2 server-emitted KeepAlive ids fit in i32 for any realistic
    // proxy lifetime; truncate.
    let id_i32 = id_i64 as i32;
    let mut out = BytesMut::with_capacity(4);
    out.put_i32(id_i32);
    ConversionResult::Converted(vec![build_payload(V164_C2S_KEEP_ALIVE, &out)])
}

/// 1.12.2 Chat c2s: VarInt-prefixed UTF-8 string (max 256 chars).
/// 1.6.4 Chat c2s: u16 BE length + UCS-2 BE string (max 100 chars).
fn c2s_chat(mut body: Bytes) -> ConversionResult {
    let Ok(msg) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    // 1.6.4 caps chat at 100 chars; truncate by char count.
    let truncated: String = msg.chars().take(100).collect();
    let units: Vec<u16> = truncated.encode_utf16().collect();
    let mut out = BytesMut::with_capacity(2 + units.len() * 2);
    if units.len() > u16::MAX as usize {
        // pathological; refuse rather than silently truncate to 0
        return ConversionResult::Passthrough;
    }
    out.put_u16(units.len() as u16);
    for u in &units {
        out.put_u16(*u);
    }
    ConversionResult::Converted(vec![build_payload(V164_C2S_CHAT, &out)])
}

/// 1.12.2 PlayerPositionAndLook c2s (id 0x0E): 3×f64, 2×f32, bool on_ground
/// = 33 bytes. No stance / head_y in c2s direction.
/// 1.6.4 PlayerPositionAndLook c2s (id 0x0D = Packet13PlayerLookMove):
/// f64 x, f64 stance, f64 y, f64 z, f32 yaw, f32 pitch, bool on_ground
/// = 41 bytes. Field order verified via MCP-doc constructor signature.
/// Synthetic stance = y + 1.62 (eye-height offset from player feet to
/// camera; this is what the Notchian client itself emits).
fn c2s_player_pos_look(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 33 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_f64();
    let y = body.get_f64();
    let z = body.get_f64();
    let yaw = body.get_f32();
    let pitch = body.get_f32();
    let on_ground = body.get_u8() != 0;

    let mut out = BytesMut::with_capacity(41);
    out.put_f64(x);
    out.put_f64(y + 1.62); // stance — synthetic eye-height offset
    out.put_f64(y);
    out.put_f64(z);
    out.put_f32(yaw);
    out.put_f32(pitch);
    out.put_u8(if on_ground { 1 } else { 0 });
    ConversionResult::Converted(vec![build_payload(V164_C2S_PLAYER_POS_LOOK, &out)])
}

/// 1.12.2 PlayerDigging c2s (id 0x14): VarInt status, Position location,
///   i8 face.
/// 1.6.4 PlayerDigging c2s (id 0x0E = Packet14BlockDig): i8 status,
///   i32 x, i8 y, i32 z, i8 face.
fn c2s_player_digging(mut body: Bytes) -> ConversionResult {
    let Ok(status_v) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.remaining() < 8 + 1 {
        return ConversionResult::Passthrough;
    }
    let packed = body.get_i64();
    // 1.12.2 source is in the legacy (1.8-1.13) packed-Position layout.
    let (x, y, z) = (
        kojacoord_protocol::types::decode_legacy_position(packed as u64).x,
        kojacoord_protocol::types::decode_legacy_position(packed as u64).y,
        kojacoord_protocol::types::decode_legacy_position(packed as u64).z,
    );
    let face = body.get_i8();

    let mut out = BytesMut::with_capacity(1 + 4 + 1 + 4 + 1);
    out.put_i8(status_v.0 as i8);
    out.put_i32(x);
    out.put_i8(y as i8);
    out.put_i32(z);
    out.put_i8(face);
    ConversionResult::Converted(vec![build_payload(V164_C2S_PLAYER_DIGGING, &out)])
}

/// 1.12.2 HeldItemChange c2s (id 0x1A): i16 slot.
/// 1.6.4 HeldItemChange c2s (id 0x10 = Packet16BlockItemSwitch): i16 slot.
/// Wire shape unchanged; only the packet id differs.
fn c2s_held_item_change(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let slot = body.get_i16();
    let mut out = BytesMut::with_capacity(2);
    out.put_i16(slot);
    ConversionResult::Converted(vec![build_payload(V164_C2S_HELD_ITEM_CHANGE, &out)])
}

/// 1.12.2 Animation c2s (id 0x1D): VarInt hand (0=main, 1=offhand).
/// 1.6.4 Animation c2s (id 0x12 = Packet18Animation): i32 entityId,
///   i8 animation (1 = swing arm).
/// We always send entity_id=0 (server fills the real id) and animation=1.
fn c2s_animation(_body: Bytes) -> ConversionResult {
    let mut out = BytesMut::with_capacity(4 + 1);
    out.put_i32(0);
    out.put_i8(1);
    ConversionResult::Converted(vec![build_payload(V164_C2S_ANIMATION, &out)])
}

/// 1.12.2 ClientSettings c2s (id 0x04): String locale (max 16), i8
///   view_distance, VarInt chat_mode, bool chat_colors, u8 displayed_skin_parts,
///   VarInt main_hand.
/// 1.6.4 ClientSettings c2s (id 0xCC = PacketCCSettings, "Client
///   Information"): UCS-2 locale, i8 view_distance, i8 chat_flags,
///   i8 difficulty, bool show_cape.
fn c2s_client_settings(mut body: Bytes) -> ConversionResult {
    let Ok(locale) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let view_distance = body.get_i8();
    let Ok(chat_mode) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let _chat_colors = body.get_u8();
    // Remaining 1.12.2 fields (displayed_skin_parts u8, main_hand VarInt)
    // have no 1.6.4 equivalent — discarded.

    // Encode locale as UCS-2 BE (truncate to 16 chars per spec).
    let locale_trunc: String = locale.chars().take(16).collect();
    let locale_chars: Vec<u16> = locale_trunc.encode_utf16().collect();
    let mut out = BytesMut::new();
    out.put_u16(locale_chars.len() as u16);
    for c in &locale_chars {
        out.put_u16(*c);
    }
    out.put_i8(view_distance);
    out.put_i8(chat_mode.0 as i8); // 1.6.4 chat_flags bitfield (0=enabled is close enough)
    out.put_i8(0); // difficulty placeholder — server overrides anyway
    out.put_u8(1); // show_cape — true is the 1.6.4 default
    ConversionResult::Converted(vec![build_payload(V164_C2S_CLIENT_SETTINGS, &out)])
}

/// 1.12.2 EntityAction c2s (id 0x15): VarInt entity_id, VarInt action_id,
///   VarInt jump_boost.
/// 1.6.4 EntityAction c2s (id 0x13 = Packet19EntityAction): i32 entity_id,
///   i8 action_id.
fn c2s_entity_action(mut body: Bytes) -> ConversionResult {
    let Ok(entity_id) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let Ok(action_id) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    // Discard jump_boost — no 1.6.4 equivalent.

    let mut out = BytesMut::with_capacity(4 + 1);
    out.put_i32(entity_id.0);
    out.put_i8(action_id.0 as i8);
    ConversionResult::Converted(vec![build_payload(V164_C2S_ENTITY_ACTION, &out)])
}

/// 1.12.2 ClientStatus c2s (id 0x03): VarInt action_id
///   (0 = respawn, 1 = open inventory stats).
/// 1.6.4 ClientCommand c2s (id 0x16 = Packet22ClientCommand): i8 payload
///   (0 = respawn, 1 = open inventory stats).
fn c2s_client_status(mut body: Bytes) -> ConversionResult {
    let Ok(action) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::with_capacity(1);
    out.put_i8(action.0 as i8);
    ConversionResult::Converted(vec![build_payload(V164_C2S_CLIENT_COMMAND, &out)])
}

/// 1.12.2 CloseWindow c2s (id 0x08): u8 window_id.
/// 1.6.4 CloseWindow c2s (id 0x65 = Packet101CloseWindow): u8 window_id.
fn c2s_close_window(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let wid = body.get_u8();
    let mut out = BytesMut::with_capacity(1);
    out.put_u8(wid);
    ConversionResult::Converted(vec![build_payload(V164_C2S_CLOSE_WINDOW, &out)])
}

/// 1.12.2 PluginMessage c2s (id 0x09): String channel, raw bytes (rest).
/// 1.6.4 PluginMessage c2s (id 0xFA = PacketFAPluginMessage):
///   UCS-2 BE channel, u16 BE length, raw bytes.
fn c2s_plugin_message(mut body: Bytes) -> ConversionResult {
    let Ok(channel) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    // The remainder of the buffer is the raw plugin payload.
    let data = body.copy_to_bytes(body.remaining()).to_vec();
    if data.len() > u16::MAX as usize {
        return ConversionResult::Passthrough;
    }

    let chars: Vec<u16> = channel.encode_utf16().collect();
    let mut out = BytesMut::new();
    out.put_u16(chars.len() as u16);
    for c in &chars {
        out.put_u16(*c);
    }
    out.put_u16(data.len() as u16);
    out.extend_from_slice(&data);
    ConversionResult::Converted(vec![build_payload(V164_C2S_PLUGIN_MESSAGE, &out)])
}

/// 1.12.2 UseEntity c2s (id 0x0A): VarInt target, VarInt type
///   (0=interact, 1=attack, 2=interact_at), optional 3xf32 cursor +
///   VarInt hand.
/// 1.6.4 UseEntity c2s (id 0x07 = Packet7UseEntity): i32 user (self
///   entity_id), i32 target, bool leftClick (true = attack).
/// We synthesise user=-1 because the proxy doesn't know it here.
fn c2s_use_entity(mut body: Bytes) -> ConversionResult {
    let Ok(target) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let Ok(type_) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let left_click = type_.0 == 1; // 1 = attack
    let mut out = BytesMut::with_capacity(4 + 4 + 1);
    out.put_i32(-1); // user — server overrides
    out.put_i32(target.0);
    out.put_u8(if left_click { 1 } else { 0 });
    ConversionResult::Converted(vec![build_payload(V164_C2S_USE_ENTITY, &out)])
}

/// 1.12.2 PlayerPosition c2s (id 0x0C): 3xf64, bool on_ground.
/// 1.6.4 PlayerPosition c2s (id 0x0B = Packet11PlayerPosition):
///   f64 x, f64 y, f64 stance, f64 z, bool on_ground = 33 bytes.
fn c2s_move_player_pos(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 25 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_f64();
    let y = body.get_f64();
    let z = body.get_f64();
    let on_ground = body.get_u8() != 0;

    let mut out = BytesMut::with_capacity(33);
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(y + 1.62); // synthetic stance
    out.put_f64(z);
    out.put_u8(if on_ground { 1 } else { 0 });
    ConversionResult::Converted(vec![build_payload(V164_C2S_MOVE_PLAYER_POS, &out)])
}

/// 1.12.2 PlayerLook c2s (id 0x0F): f32 yaw, f32 pitch, bool on_ground.
/// 1.6.4 PlayerLook c2s (id 0x0C = Packet12PlayerLook): f32 yaw,
///   f32 pitch, bool on_ground. Shape unchanged.
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
    ConversionResult::Converted(vec![build_payload(V164_C2S_MOVE_PLAYER_ROT, &out)])
}

/// 1.12.2 PlayerAbilities c2s (id 0x13): i8 flags, f32 flying_speed,
///   f32 walking_speed.
/// 1.6.4 PlayerAbilities c2s (id 0xCA = PacketCAPlayerAbilities):
///   i8 flags, f32 flying_speed, f32 walking_speed. Shape unchanged.
fn c2s_player_abilities(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 9 {
        return ConversionResult::Passthrough;
    }
    let flags = body.get_i8();
    let flying = body.get_f32();
    let walking = body.get_f32();
    let mut out = BytesMut::with_capacity(9);
    out.put_i8(flags);
    out.put_f32(flying);
    out.put_f32(walking);
    ConversionResult::Converted(vec![build_payload(V164_C2S_PLAYER_ABILITIES, &out)])
}

/// 1.12.2 UpdateSign c2s (id 0x1C): Position location, 4 String lines.
/// 1.6.4 UpdateSign c2s (id 0x82 = Packet130UpdateSign):
///   i32 x, i16 y, i32 z, 4 UCS-2 BE lines.
fn c2s_update_sign(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let packed = body.get_i64();
    let pos = kojacoord_protocol::types::decode_legacy_position(packed as u64);

    let mut lines: [Option<String>; 4] = [None, None, None, None];
    for line in lines.iter_mut() {
        if let Ok(s) = String::decode(&mut body) {
            *line = Some(s);
        }
    }

    let mut out = BytesMut::new();
    out.put_i32(pos.x);
    out.put_i16(pos.y as i16);
    out.put_i32(pos.z);
    for line in lines {
        let s = line.unwrap_or_default();
        let chars: Vec<u16> = s
            .chars()
            .take(15)
            .collect::<String>()
            .encode_utf16()
            .collect();
        out.put_u16(chars.len() as u16);
        for c in &chars {
            out.put_u16(*c);
        }
    }
    ConversionResult::Converted(vec![build_payload(V164_C2S_UPDATE_SIGN, &out)])
}

/// 1.12.2 PlayerBlockPlacement c2s (id 0x1F): Position location,
///   VarInt face, VarInt hand, 3xf32 cursor.
/// 1.6.4 PlayerBlockPlacement c2s (id 0x0F = Packet15Place):
///   i32 x, u8 y, i32 z, i8 direction, Slot held_item, i8 cursor_x,
///   i8 cursor_y, i8 cursor_z.
///
/// 1.6.4 requires a `Slot` for the held_item field, but the 1.12.2 c2s
/// packet doesn't carry one — the server tracks the slot itself. Emit
/// an empty slot (i16 = -1) which matches what 1.6.4 clients send for
/// air placement.
fn c2s_player_block_placement(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let packed = body.get_i64();
    let pos = kojacoord_protocol::types::decode_legacy_position(packed as u64);
    let Ok(face) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let Ok(_hand) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.remaining() < 12 {
        return ConversionResult::Passthrough;
    }
    let cx = body.get_f32();
    let cy = body.get_f32();
    let cz = body.get_f32();

    let mut out = BytesMut::new();
    out.put_i32(pos.x);
    out.put_u8(pos.y as u8);
    out.put_i32(pos.z);
    out.put_i8(face.0 as i8);
    // Empty Slot: i16 item_id = -1.
    out.put_i16(-1);
    // Cursor coords scaled to i8 range [0, 15].
    out.put_i8((cx * 16.0).clamp(0.0, 15.0) as i8);
    out.put_i8((cy * 16.0).clamp(0.0, 15.0) as i8);
    out.put_i8((cz * 16.0).clamp(0.0, 15.0) as i8);
    ConversionResult::Converted(vec![build_payload(V164_C2S_PLAYER_BLOCK_PLACEMENT, &out)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_alive_truncates_i64_to_i32() {
        let mut body = BytesMut::new();
        body.put_i64(0x0000_0000_DEAD_BEEFu64 as i64);
        let payload = build_payload(V112_C2S_KEEP_ALIVE, &body);
        let res = convert_c2s(payload);
        match res {
            ConversionResult::Converted(mut pkts) => {
                let mut out = pkts.remove(0);
                let id = VarInt::decode(&mut out).unwrap().0 as u8;
                assert_eq!(id, V164_C2S_KEEP_ALIVE);
                assert_eq!(out.get_i32(), 0xDEAD_BEEFu32 as i32);
            },
            other => panic!(
                "expected Converted, got {:?}",
                core::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn chat_encodes_ucs2_big_endian() {
        let msg = "Hi";
        let mut body = BytesMut::new();
        VarInt(msg.len() as i32).encode(&mut body).unwrap();
        body.extend_from_slice(msg.as_bytes());
        let payload = build_payload(V112_C2S_CHAT, &body);
        let res = convert_c2s(payload);
        match res {
            ConversionResult::Converted(mut pkts) => {
                let mut out = pkts.remove(0);
                let id = VarInt::decode(&mut out).unwrap().0 as u8;
                assert_eq!(id, V164_C2S_CHAT);
                assert_eq!(out.get_u16(), 2); // char count
                assert_eq!(out.get_u16(), 0x0048); // 'H' big-endian
                assert_eq!(out.get_u16(), 0x0069); // 'i' big-endian
            },
            other => panic!(
                "expected Converted, got {:?}",
                core::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn chat_truncates_to_100_chars() {
        let msg = "X".repeat(200);
        let mut body = BytesMut::new();
        VarInt(msg.len() as i32).encode(&mut body).unwrap();
        body.extend_from_slice(msg.as_bytes());
        let payload = build_payload(V112_C2S_CHAT, &body);
        let res = convert_c2s(payload);
        match res {
            ConversionResult::Converted(mut pkts) => {
                let mut out = pkts.remove(0);
                let _id = VarInt::decode(&mut out).unwrap();
                let n = out.get_u16();
                assert_eq!(n, 100, "1.6.4 chat capped at 100 chars");
            },
            other => panic!(
                "expected Converted, got {:?}",
                core::mem::discriminant(&other)
            ),
        }
    }
}
