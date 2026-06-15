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
use kojacoord_protocol::codec::{Decode, Encode};
use kojacoord_protocol::types::VarInt;

use super::{build_payload, split_id};
use crate::converter::ConversionResult;

// ---- 1.12.2 source ids (per registry proto 340 / BungeeCord
// `Protocol.java::TO_SERVER`) ----
const V112_C2S_TELEPORT_CONFIRM: u8 = 0x00;
const V112_C2S_TAB_COMPLETE: u8 = 0x01;
const V112_C2S_CHAT: u8 = 0x02;
const V112_C2S_CLIENT_STATUS: u8 = 0x03;
const V112_C2S_CLIENT_SETTINGS: u8 = 0x04;
const V112_C2S_CONFIRM_TRANSACTION: u8 = 0x05;
const V112_C2S_ENCHANT_ITEM: u8 = 0x06;
const V112_C2S_WINDOW_CLICK: u8 = 0x07;
const V112_C2S_CLOSE_WINDOW: u8 = 0x08;
const V112_C2S_PLUGIN_MESSAGE: u8 = 0x09;
const V112_C2S_USE_ENTITY: u8 = 0x0A;
const V112_C2S_KEEP_ALIVE: u8 = 0x0B;
const V112_C2S_MOVE_PLAYER_POS: u8 = 0x0C;
const V112_C2S_PLAYER_POS: u8 = 0x0D;
const V112_C2S_PLAYER_POS_LOOK: u8 = 0x0E;
const V112_C2S_MOVE_PLAYER_ROT: u8 = 0x0F;
const V112_C2S_STEER_VEHICLE: u8 = 0x16;
const V112_C2S_PLAYER_ABILITIES: u8 = 0x13;
const V112_C2S_PLAYER_DIGGING: u8 = 0x14;
const V112_C2S_ENTITY_ACTION: u8 = 0x15;
const V112_C2S_HELD_ITEM_CHANGE: u8 = 0x1A;
const V112_C2S_CREATIVE_INV: u8 = 0x1B;
const V112_C2S_UPDATE_SIGN: u8 = 0x1C;
const V112_C2S_ANIMATION: u8 = 0x1D;
const V112_C2S_PLAYER_BLOCK_PLACEMENT: u8 = 0x1F;
const V112_C2S_USE_ITEM: u8 = 0x20;

// ---- 1.6.4 target ids (MCP-doc decimal = hex) ----
const V164_C2S_KEEP_ALIVE: u8 = 0x00;
const V164_C2S_CHAT: u8 = 0x03;
const V164_C2S_USE_ENTITY: u8 = 0x07;
#[allow(dead_code)]
const V164_C2S_PLAYER_ON_GROUND: u8 = 0x0A;
const V164_C2S_MOVE_PLAYER_POS: u8 = 0x0B;
const V164_C2S_MOVE_PLAYER_ROT: u8 = 0x0C;
const V164_C2S_PLAYER_POS_LOOK: u8 = 0x0D;
const V164_C2S_PLAYER_DIGGING: u8 = 0x0E;
const V164_C2S_PLAYER_BLOCK_PLACEMENT: u8 = 0x0F;
const V164_C2S_HELD_ITEM_CHANGE: u8 = 0x10;
const V164_C2S_ANIMATION: u8 = 0x12;
const V164_C2S_ENTITY_ACTION: u8 = 0x13;
const V164_C2S_STEER_VEHICLE: u8 = 0x1B;
const V164_C2S_CLOSE_WINDOW: u8 = 0x65;
const V164_C2S_WINDOW_CLICK: u8 = 0x66;
const V164_C2S_CONFIRM_TRANSACTION: u8 = 0x6A;
const V164_C2S_CREATIVE_INV: u8 = 0x6B;
const V164_C2S_ENCHANT_ITEM: u8 = 0x6C;
const V164_C2S_UPDATE_SIGN: u8 = 0x82;
const V164_C2S_PLAYER_ABILITIES: u8 = 0xCA;
const V164_C2S_TAB_COMPLETE: u8 = 0xCB;
const V164_C2S_CLIENT_SETTINGS: u8 = 0xCC;
const V164_C2S_CLIENT_COMMAND: u8 = 0xCD;
const V164_C2S_PLUGIN_MESSAGE: u8 = 0xFA;

pub fn convert_c2s(payload: Bytes) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };
    match id {
        V112_C2S_TELEPORT_CONFIRM => ConversionResult::Drop,
        V112_C2S_TAB_COMPLETE => c2s_tab_complete(body),
        V112_C2S_KEEP_ALIVE => c2s_keep_alive(body),
        V112_C2S_CHAT => c2s_chat(body),
        V112_C2S_CLIENT_STATUS => c2s_client_status(body),
        V112_C2S_CLIENT_SETTINGS => c2s_client_settings(body),
        V112_C2S_CONFIRM_TRANSACTION => c2s_confirm_transaction(body),
        V112_C2S_ENCHANT_ITEM => c2s_enchant_item(body),
        V112_C2S_WINDOW_CLICK => c2s_window_click(body),
        V112_C2S_CLOSE_WINDOW => c2s_close_window(body),
        V112_C2S_PLUGIN_MESSAGE => c2s_plugin_message(body),
        V112_C2S_USE_ENTITY => c2s_use_entity(body),
        V112_C2S_MOVE_PLAYER_POS => c2s_move_player_pos(body),
        V112_C2S_PLAYER_POS_LOOK => c2s_player_pos_look(body),
        V112_C2S_MOVE_PLAYER_ROT => c2s_move_player_rot(body),
        V112_C2S_STEER_VEHICLE => c2s_steer_vehicle(body),
        V112_C2S_PLAYER_ABILITIES => c2s_player_abilities(body),
        V112_C2S_PLAYER_DIGGING => c2s_player_digging(body),
        V112_C2S_ENTITY_ACTION => c2s_entity_action(body),
        V112_C2S_HELD_ITEM_CHANGE => c2s_held_item_change(body),
        V112_C2S_CREATIVE_INV => c2s_creative_inv(body),
        V112_C2S_UPDATE_SIGN => c2s_update_sign(body),
        V112_C2S_ANIMATION => c2s_animation(body),
        V112_C2S_PLAYER_BLOCK_PLACEMENT => c2s_player_block_placement(body),
        V112_C2S_USE_ITEM => ConversionResult::Drop,
        // 1.12.2 packets with no 1.6.4 C2S equivalent
        0x10 | 0x11 | 0x12 | 0x17 | 0x18 | 0x19 | 0x1E => ConversionResult::Drop,
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

// ═══════════════════════════════════════════════════════════════════
// SERVERBOUND-TO-CLIENT (s2c): 1.12.2 backend packets → 1.6.4 client
// ═══════════════════════════════════════════════════════════════════
//
// Sourced against:
//   * BungeeCord `Protocol.java::TO_CLIENT` proto 340 (1.12.2 ids)
//   * HexaCord / KettleCord pre-netty Packet<N><Name>.java (1.6.4 ids)
//   * minecraft.wiki Java_Edition_protocol/Packets per-version pages
//
// Packets the 1.6.4 client cannot render at all (post-1.6 additions:
// SetCooldown, UnlockRecipes, Advancements, WorldBorder, Camera, etc.)
// are explicitly dropped rather than passed through — the 1.6.4 client
// would reject the unknown packet id and disconnect with "Bad packet id".

// ---- 1.12.2 source ids (s2c, per BungeeCord proto 340) ----
const V112_S2C_SPAWN_OBJECT: u8 = 0x00;
const V112_S2C_SPAWN_EXP_ORB: u8 = 0x01;
const V112_S2C_SPAWN_GLOBAL: u8 = 0x02;
const V112_S2C_SPAWN_MOB: u8 = 0x03;
const V112_S2C_SPAWN_PAINTING: u8 = 0x04;
const V112_S2C_SPAWN_PLAYER: u8 = 0x05;
const V112_S2C_ANIMATION: u8 = 0x06;
const V112_S2C_STATISTICS: u8 = 0x07;
const V112_S2C_BLOCK_BREAK_ANIM: u8 = 0x08;
const V112_S2C_TILE_ENTITY_DATA: u8 = 0x09;
const V112_S2C_BLOCK_ACTION: u8 = 0x0A;
const V112_S2C_BLOCK_CHANGE: u8 = 0x0B;
const V112_S2C_TAB_COMPLETE: u8 = 0x0E;
const V112_S2C_CHAT: u8 = 0x0F;
const V112_S2C_CONFIRM_TRANSACTION: u8 = 0x11;
const V112_S2C_CLOSE_WINDOW: u8 = 0x12;
const V112_S2C_OPEN_WINDOW: u8 = 0x13;
const V112_S2C_WINDOW_ITEMS: u8 = 0x14;
const V112_S2C_WINDOW_PROPERTY: u8 = 0x15;
const V112_S2C_SET_SLOT: u8 = 0x16;
const V112_S2C_PLUGIN_MESSAGE: u8 = 0x18;
const V112_S2C_NAMED_SOUND: u8 = 0x19;
const V112_S2C_DISCONNECT: u8 = 0x1A;
const V112_S2C_ENTITY_STATUS: u8 = 0x1B;
const V112_S2C_EXPLOSION: u8 = 0x1C;
const V112_S2C_GAME_STATE: u8 = 0x1E;
const V112_S2C_KEEP_ALIVE: u8 = 0x1F;
const V112_S2C_EFFECT: u8 = 0x21;
const V112_S2C_PARTICLE: u8 = 0x22;
const V112_S2C_JOIN_GAME: u8 = 0x23;
const V112_S2C_ENTITY: u8 = 0x25;
const V112_S2C_ENTITY_REL_MOVE: u8 = 0x26;
const V112_S2C_ENTITY_LOOK_REL_MOVE: u8 = 0x27;
const V112_S2C_ENTITY_LOOK: u8 = 0x28;
const V112_S2C_OPEN_SIGN_EDITOR: u8 = 0x2A;
const V112_S2C_PLAYER_ABILITIES: u8 = 0x2C;
const V112_S2C_PLAYER_POS_LOOK: u8 = 0x2F;
const V112_S2C_DESTROY_ENTITIES: u8 = 0x32;
const V112_S2C_REMOVE_ENTITY_EFFECT: u8 = 0x33;
const V112_S2C_RESPAWN: u8 = 0x35;
const V112_S2C_ENTITY_HEAD_LOOK: u8 = 0x36;
const V112_S2C_HELD_ITEM_CHANGE: u8 = 0x3A;
const V112_S2C_DISPLAY_SCOREBOARD: u8 = 0x3B;
const V112_S2C_ENTITY_METADATA: u8 = 0x3C;
const V112_S2C_ATTACH_ENTITY: u8 = 0x3D;
const V112_S2C_ENTITY_VELOCITY: u8 = 0x3E;
const V112_S2C_ENTITY_EQUIPMENT: u8 = 0x3F;
const V112_S2C_SET_EXPERIENCE: u8 = 0x40;
const V112_S2C_UPDATE_HEALTH: u8 = 0x41;
const V112_S2C_SCOREBOARD_OBJ: u8 = 0x42;
const V112_S2C_TEAMS: u8 = 0x44;
const V112_S2C_UPDATE_SCORE: u8 = 0x45;
const V112_S2C_SPAWN_POSITION: u8 = 0x46;
const V112_S2C_TIME_UPDATE: u8 = 0x47;
const V112_S2C_COLLECT_ITEM: u8 = 0x4B;
const V112_S2C_ENTITY_TELEPORT: u8 = 0x4C;
const V112_S2C_ENTITY_PROPERTIES: u8 = 0x4E;
const V112_S2C_ENTITY_EFFECT: u8 = 0x4F;

// ---- 1.6.4 target ids (s2c, MCP-doc decimal = hex) ----
const V164_S2C_KEEP_ALIVE: u8 = 0x00;
const V164_S2C_LOGIN_REQUEST: u8 = 0x01;
const V164_S2C_CHAT: u8 = 0x03;
const V164_S2C_TIME_UPDATE: u8 = 0x04;
const V164_S2C_ENTITY_EQUIPMENT: u8 = 0x05;
const V164_S2C_SPAWN_POSITION: u8 = 0x06;
const V164_S2C_UPDATE_HEALTH: u8 = 0x08;
const V164_S2C_RESPAWN: u8 = 0x09;
const V164_S2C_PLAYER_POS_LOOK: u8 = 0x0D;
const V164_S2C_HELD_ITEM_CHANGE: u8 = 0x10;
const V164_S2C_ANIMATION: u8 = 0x12;
const V164_S2C_SPAWN_PLAYER: u8 = 0x14;
const V164_S2C_COLLECT_ITEM: u8 = 0x16;
const V164_S2C_SPAWN_OBJECT: u8 = 0x17;
const V164_S2C_SPAWN_MOB: u8 = 0x18;
const V164_S2C_SPAWN_PAINTING: u8 = 0x19;
const V164_S2C_SPAWN_EXP_ORB: u8 = 0x1A;
const V164_S2C_ENTITY_VELOCITY: u8 = 0x1C;
const V164_S2C_DESTROY_ENTITIES: u8 = 0x1D;
const V164_S2C_ENTITY: u8 = 0x1E;
const V164_S2C_ENTITY_REL_MOVE: u8 = 0x1F;
const V164_S2C_ENTITY_LOOK: u8 = 0x20;
const V164_S2C_ENTITY_LOOK_REL_MOVE: u8 = 0x21;
const V164_S2C_ENTITY_TELEPORT: u8 = 0x22;
const V164_S2C_ENTITY_HEAD_LOOK: u8 = 0x23;
const V164_S2C_ENTITY_STATUS: u8 = 0x26;
const V164_S2C_ATTACH_ENTITY: u8 = 0x27;
const V164_S2C_ENTITY_METADATA: u8 = 0x28;
const V164_S2C_ENTITY_EFFECT: u8 = 0x29;
const V164_S2C_REMOVE_ENTITY_EFFECT: u8 = 0x2A;
const V164_S2C_SET_EXPERIENCE: u8 = 0x2B;
const V164_S2C_ENTITY_PROPERTIES: u8 = 0x2C;
const V164_S2C_BLOCK_CHANGE: u8 = 0x35;
const V164_S2C_BLOCK_ACTION: u8 = 0x36;
const V164_S2C_BLOCK_BREAK_ANIM: u8 = 0x37;
const V164_S2C_EXPLOSION: u8 = 0x3C;
const V164_S2C_EFFECT: u8 = 0x3D;
const V164_S2C_NAMED_SOUND: u8 = 0x3E;
const V164_S2C_PARTICLE: u8 = 0x3F;
const V164_S2C_GAME_STATE: u8 = 0x46;
const V164_S2C_SPAWN_GLOBAL: u8 = 0x47;
const V164_S2C_OPEN_WINDOW: u8 = 0x64;
const V164_S2C_CLOSE_WINDOW: u8 = 0x65;
const V164_S2C_SET_SLOT: u8 = 0x67;
const V164_S2C_WINDOW_ITEMS: u8 = 0x68;
const V164_S2C_WINDOW_PROPERTY: u8 = 0x69;
const V164_S2C_CONFIRM_TRANSACTION: u8 = 0x6A;
const V164_S2C_UPDATE_SIGN: u8 = 0x82;
const V164_S2C_TILE_ENTITY_DATA: u8 = 0x84;
const V164_S2C_OPEN_SIGN_EDITOR: u8 = 0x85;
const V164_S2C_STATISTIC: u8 = 0xC8;
const V164_S2C_PLAYER_INFO: u8 = 0xC9;
const V164_S2C_PLAYER_ABILITIES: u8 = 0xCA;
const V164_S2C_TAB_COMPLETE: u8 = 0xCB;
const V164_S2C_SCOREBOARD_OBJ: u8 = 0xCE;
const V164_S2C_UPDATE_SCORE: u8 = 0xCF;
const V164_S2C_DISPLAY_SCOREBOARD: u8 = 0xD0;
const V164_S2C_TEAMS: u8 = 0xD1;
const V164_S2C_PLUGIN_MESSAGE: u8 = 0xFA;
const V164_S2C_DISCONNECT: u8 = 0xFF;

pub fn convert_s2c(payload: Bytes) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };
    match id {
        V112_S2C_KEEP_ALIVE => s2c_keep_alive(body),
        V112_S2C_JOIN_GAME => s2c_join_game(body),
        V112_S2C_CHAT => s2c_chat(body),
        V112_S2C_TIME_UPDATE => s2c_time_update(body),
        V112_S2C_SPAWN_POSITION => s2c_spawn_position(body),
        V112_S2C_UPDATE_HEALTH => s2c_update_health(body),
        V112_S2C_RESPAWN => s2c_respawn(body),
        V112_S2C_PLAYER_POS_LOOK => s2c_player_pos_look(body),
        V112_S2C_HELD_ITEM_CHANGE => s2c_held_item_change(body),
        V112_S2C_PLAYER_ABILITIES => s2c_player_abilities(body),
        V112_S2C_DISCONNECT => s2c_disconnect(body),
        V112_S2C_PLUGIN_MESSAGE => s2c_plugin_message(body),
        V112_S2C_BLOCK_CHANGE => s2c_block_change(body),
        V112_S2C_SPAWN_PLAYER => s2c_spawn_player(body),
        V112_S2C_SPAWN_OBJECT => s2c_spawn_object(body),
        V112_S2C_SPAWN_MOB => s2c_spawn_mob(body),
        V112_S2C_SPAWN_PAINTING => s2c_spawn_painting(body),
        V112_S2C_SPAWN_EXP_ORB => s2c_spawn_exp_orb(body),
        V112_S2C_SPAWN_GLOBAL => s2c_spawn_global(body),
        V112_S2C_ENTITY => s2c_entity(body),
        V112_S2C_ENTITY_REL_MOVE => s2c_entity_rel_move(body),
        V112_S2C_ENTITY_LOOK => s2c_entity_look(body),
        V112_S2C_ENTITY_LOOK_REL_MOVE => s2c_entity_look_rel_move(body),
        V112_S2C_ENTITY_TELEPORT => s2c_entity_teleport(body),
        V112_S2C_ENTITY_HEAD_LOOK => s2c_entity_head_look(body),
        V112_S2C_ENTITY_STATUS => s2c_entity_status(body),
        V112_S2C_ATTACH_ENTITY => s2c_attach_entity(body),
        V112_S2C_ENTITY_METADATA => s2c_entity_metadata(body),
        V112_S2C_ENTITY_EFFECT => s2c_entity_effect(body),
        V112_S2C_REMOVE_ENTITY_EFFECT => s2c_remove_entity_effect(body),
        V112_S2C_SET_EXPERIENCE => s2c_set_experience(body),
        V112_S2C_ENTITY_PROPERTIES => s2c_entity_properties(body),
        V112_S2C_DESTROY_ENTITIES => s2c_destroy_entities(body),
        V112_S2C_COLLECT_ITEM => s2c_collect_item(body),
        V112_S2C_ENTITY_EQUIPMENT => s2c_entity_equipment(body),
        V112_S2C_ENTITY_VELOCITY => s2c_entity_velocity(body),
        V112_S2C_ANIMATION => s2c_animation(body),
        V112_S2C_BLOCK_BREAK_ANIM => s2c_block_break_anim(body),
        V112_S2C_BLOCK_ACTION => s2c_block_action(body),
        V112_S2C_TILE_ENTITY_DATA => s2c_tile_entity_data(body),
        V112_S2C_OPEN_WINDOW => s2c_open_window(body),
        V112_S2C_CLOSE_WINDOW => s2c_close_window(body),
        V112_S2C_SET_SLOT => s2c_set_slot(body),
        V112_S2C_WINDOW_ITEMS => s2c_window_items(body),
        V112_S2C_WINDOW_PROPERTY => s2c_window_property(body),
        V112_S2C_CONFIRM_TRANSACTION => s2c_confirm_transaction(body),
        V112_S2C_OPEN_SIGN_EDITOR => s2c_open_sign_editor(body),
        V112_S2C_STATISTICS => s2c_statistics(body),
        V112_S2C_TAB_COMPLETE => s2c_tab_complete(body),
        V112_S2C_SCOREBOARD_OBJ => s2c_scoreboard_obj(body),
        V112_S2C_UPDATE_SCORE => s2c_update_score(body),
        V112_S2C_DISPLAY_SCOREBOARD => s2c_display_scoreboard(body),
        V112_S2C_TEAMS => s2c_teams(body),
        V112_S2C_EFFECT => s2c_effect(body),
        V112_S2C_NAMED_SOUND => s2c_named_sound(body),
        V112_S2C_EXPLOSION => s2c_explosion(body),
        V112_S2C_GAME_STATE => s2c_game_state(body),
        V112_S2C_PARTICLE => {
            tracing::debug!(target: "converter", "1.12.2→1.6.4: particle dropped (string→id mapping needed)");
            ConversionResult::Drop
        },
        // Drop post-1.6 additions that have no pre-netty equivalent.
        0x0C | 0x0D | 0x17 | 0x1D | 0x29 | 0x2B | 0x2D | 0x30
        | 0x31 | 0x34 | 0x37 | 0x38 | 0x39 | 0x43 | 0x48 | 0x49
        | 0x4A | 0x4D => {
            ConversionResult::Drop
        },
        _ => ConversionResult::Passthrough,
    }
}

/// 1.12.2 KeepAlive s2c: i64 id. 1.6.4 KeepAlive s2c: i32 id.
fn s2c_keep_alive(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let id = body.get_i64() as i32;
    let mut out = BytesMut::new();
    out.put_i32(id);
    ConversionResult::Converted(vec![build_payload(V164_S2C_KEEP_ALIVE, &out)])
}

/// 1.12.2 JoinGame → 1.6.4 Packet1Login (`LoginRequestS2C`).
///
/// 1.12.2 layout: `[i32 entity_id][u8 gamemode][i32 dimension]`
/// `[u8 difficulty][u8 max_players][String level_type][bool reduced_debug]`.
/// 1.6.4 Packet1Login: `[i32 entity_id][UCS-2 level_type][i8 gamemode]`
/// `[i8 dimension][i8 difficulty][u8 world_height][u8 max_players]`.
///
/// Fields are reordered: level_type moves to position 2 (was 5).
fn s2c_join_game(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 1 + 4 + 1 + 1 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body.get_i32();
    let gamemode = body.get_u8();
    let dimension = body.get_i32() as i8; // 1.6 stores dimension as i8
    let difficulty = body.get_u8();
    let max_players = body.get_u8();
    let Ok(level_type) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };

    let mut out = BytesMut::new();
    out.put_i32(entity_id);
    encode_legacy_string(&level_type, &mut out);
    out.put_i8(gamemode as i8);
    out.put_i8(dimension);
    out.put_i8(difficulty as i8);
    out.put_u8(0); // world_height — unused in 1.6.4
    out.put_u8(max_players);
    ConversionResult::Converted(vec![build_payload(V164_S2C_LOGIN_REQUEST, &out)])
}

/// 1.12.2 Chat s2c: `[VarInt-String json][i8 position]`.
/// 1.6.4 Chat s2c: `[UCS-2 String json]` (no position).
/// Position byte is dropped — 1.6.4 only had the chat-line slot.
fn s2c_chat(mut body: Bytes) -> ConversionResult {
    let Ok(json) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    encode_legacy_string(&json, &mut out);
    ConversionResult::Converted(vec![build_payload(V164_S2C_CHAT, &out)])
}

/// 1.12.2 TimeUpdate: `[i64 world_age][i64 time_of_day]`.
/// 1.6.4 TimeUpdate: same shape.
fn s2c_time_update(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 16 {
        return ConversionResult::Passthrough;
    }
    let world_age = body.get_i64();
    let time_of_day = body.get_i64();
    let mut out = BytesMut::new();
    out.put_i64(world_age);
    out.put_i64(time_of_day);
    ConversionResult::Converted(vec![build_payload(V164_S2C_TIME_UPDATE, &out)])
}

/// 1.12.2 SpawnPosition: `[i64 packed Position]`.
/// 1.6.4 SpawnPosition: `[i32 x][i32 y][i32 z]`.
fn s2c_spawn_position(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let packed = body.get_i64();
    let pos = kojacoord_protocol::types::decode_legacy_position(packed as u64);
    let mut out = BytesMut::new();
    out.put_i32(pos.x);
    out.put_i32(pos.y);
    out.put_i32(pos.z);
    ConversionResult::Converted(vec![build_payload(V164_S2C_SPAWN_POSITION, &out)])
}

/// 1.12.2 UpdateHealth: `[f32 health][VarInt food][f32 saturation]`.
/// 1.6.4 UpdateHealth: `[f32 health][i16 food][f32 saturation]`.
fn s2c_update_health(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let health = body.get_f32();
    let Ok(food) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let saturation = body.get_f32();
    let mut out = BytesMut::new();
    out.put_f32(health);
    out.put_i16(food.0 as i16);
    out.put_f32(saturation);
    ConversionResult::Converted(vec![build_payload(V164_S2C_UPDATE_HEALTH, &out)])
}

/// 1.12.2 Respawn: `[i32 dimension][u8 difficulty][u8 gamemode][String level_type]`.
/// 1.6.4 Respawn: `[i32 dimension][i8 difficulty][i8 gamemode][i16 world_height][UCS-2 level_type]`.
fn s2c_respawn(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 1 + 1 {
        return ConversionResult::Passthrough;
    }
    let dimension = body.get_i32();
    let difficulty = body.get_u8();
    let gamemode = body.get_u8();
    let Ok(level_type) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    out.put_i32(dimension);
    out.put_i8(difficulty as i8);
    out.put_i8(gamemode as i8);
    out.put_i16(256); // standard world_height for 1.6.4
    encode_legacy_string(&level_type, &mut out);
    ConversionResult::Converted(vec![build_payload(V164_S2C_RESPAWN, &out)])
}

/// 1.12.2 PlayerPositionAndLook: `[f64 x][f64 y][f64 z][f32 yaw][f32 pitch][i8 flags][VarInt teleport_id]`.
/// 1.6.4 PlayerPositionLook: `[f64 x][f64 stance][f64 y][f64 z][f32 yaw][f32 pitch][bool on_ground]`.
/// stance is synthesised as y + 1.62; teleport_id is dropped (1.6 had no ack);
/// `flags` (relative-position bitfield) is collapsed to absolute by assuming
/// flags=0 — modern servers nearly always emit absolute coords during normal play.
fn s2c_player_pos_look(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 * 3 + 4 * 2 + 1 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_f64();
    let y = body.get_f64();
    let z = body.get_f64();
    let yaw = body.get_f32();
    let pitch = body.get_f32();
    let _flags = body.get_i8();
    let _teleport_id = VarInt::decode(&mut body);
    let mut out = BytesMut::new();
    out.put_f64(x);
    out.put_f64(y + 1.62); // stance
    out.put_f64(y);
    out.put_f64(z);
    out.put_f32(yaw);
    out.put_f32(pitch);
    out.put_u8(1); // on_ground = true
    ConversionResult::Converted(vec![build_payload(V164_S2C_PLAYER_POS_LOOK, &out)])
}

/// 1.12.2 HeldItemChange s2c: `[i8 slot]`.
/// 1.6.4 HeldItemChange s2c: `[i16 slot]` (per HexaCord `Packet16BlockItemSwitch`).
fn s2c_held_item_change(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let slot = body.get_i8();
    let mut out = BytesMut::new();
    out.put_i16(slot as i16);
    ConversionResult::Converted(vec![build_payload(V164_S2C_HELD_ITEM_CHANGE, &out)])
}

/// 1.12.2 PlayerAbilities: `[i8 flags][f32 fly_speed][f32 walk_speed]`.
/// 1.6.4 PlayerAbilities: same shape.
fn s2c_player_abilities(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 + 4 + 4 {
        return ConversionResult::Passthrough;
    }
    let flags = body.get_i8();
    let fly_speed = body.get_f32();
    let walk_speed = body.get_f32();
    let mut out = BytesMut::new();
    out.put_i8(flags);
    out.put_f32(fly_speed);
    out.put_f32(walk_speed);
    ConversionResult::Converted(vec![build_payload(V164_S2C_PLAYER_ABILITIES, &out)])
}

/// 1.12.2 Disconnect: `[VarInt-String json]`.
/// 1.6.4 Disconnect (Packet255Kick): `[UCS-2 String reason]`. 1.6.x DOES
/// parse the reason as JSON (Mojang added MessageComponentSerializer in 1.6),
/// so passing the JSON straight through is correct.
fn s2c_disconnect(mut body: Bytes) -> ConversionResult {
    let Ok(reason) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    encode_legacy_string(&reason, &mut out);
    ConversionResult::Converted(vec![build_payload(V164_S2C_DISCONNECT, &out)])
}

/// 1.12.2 PluginMessage: `[VarInt-String channel][bytes data (remaining)]`.
/// 1.6.4 PluginMessage: `[UCS-2 channel][i16 data_len][bytes data]`.
/// 1.6.4 channel uses the legacy `MC|<name>` naming; 1.12.2's
/// `minecraft:<name>` channels are translated where the mapping is
/// obvious, else passed through verbatim (1.6.4 silently drops
/// unrecognised channels, which is fine).
fn s2c_plugin_message(mut body: Bytes) -> ConversionResult {
    let Ok(channel) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let legacy_channel = match channel.as_str() {
        "minecraft:brand" => "MC|Brand".to_owned(),
        other => other.to_owned(),
    };
    let data = body.to_vec();
    if data.len() > i16::MAX as usize {
        return ConversionResult::Drop; // 1.6.4 caps i16 data_len
    }
    let mut out = BytesMut::new();
    encode_legacy_string(&legacy_channel, &mut out);
    out.put_i16(data.len() as i16);
    out.put_slice(&data);
    ConversionResult::Converted(vec![build_payload(V164_S2C_PLUGIN_MESSAGE, &out)])
}

/// 1.12.2 BlockChange: `[i64 packed Position][VarInt block_state]`.
/// 1.6.4 BlockChange: `[i32 x][u8 y][i32 z][i16 block_id][u8 metadata]`.
/// Block state collapse: modern global-palette id is split into legacy
/// `(block_id, metadata)` via the flattening table — we only handle the
/// "passthrough" fallback here (assume block_state fits in i16 and
/// metadata=0). Real flattening lives in `chunk_repack`; chunk packets
/// route through that instead.
fn s2c_block_change(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let packed = body.get_i64();
    let pos = kojacoord_protocol::types::decode_legacy_position(packed as u64);
    let Ok(state) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let block_id = (state.0 >> 4).clamp(0, i16::MAX as i32) as i16;
    let metadata = (state.0 & 0xF) as u8;
    let mut out = BytesMut::new();
    out.put_i32(pos.x);
    out.put_u8(pos.y as u8);
    out.put_i32(pos.z);
    out.put_i16(block_id);
    out.put_u8(metadata);
    ConversionResult::Converted(vec![build_payload(V164_S2C_BLOCK_CHANGE, &out)])
}

/// 1.12.2 SpawnPlayer: `[VarInt entity_id][UUID player_uuid][f64 x][f64 y][f64 z]`
/// `[u8 yaw][u8 pitch][Metadata]`.
/// 1.6.4 NamedEntitySpawn: `[i32 entity_id][UCS-2 username][i32 x_fp32][i32 y_fp32]`
/// `[i32 z_fp32][i8 yaw][i8 pitch][i16 held_item][Metadata]`.
/// We synthesise username from UUID prefix (the proxy doesn't have the
/// real name here without an entity-name registry); held_item=0 (empty).
/// Modern Metadata format is incompatible — we stub it as the terminator
/// byte 0x7F so the 1.6.4 client doesn't read garbage.
fn s2c_spawn_player(mut body: Bytes) -> ConversionResult {
    let Ok(entity_id) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.remaining() < 16 + 8 * 3 + 1 + 1 {
        return ConversionResult::Passthrough;
    }
    let hi = body.get_i64();
    let lo = body.get_i64();
    let x = body.get_f64();
    let y = body.get_f64();
    let z = body.get_f64();
    let yaw = body.get_u8() as i8;
    let pitch = body.get_u8() as i8;
    // Drop the modern metadata blob entirely.
    let username = format!("p_{:x}{:x}", hi as u32, lo as u32);

    let mut out = BytesMut::new();
    out.put_i32(entity_id.0);
    encode_legacy_string(&username, &mut out);
    out.put_i32((x * 32.0) as i32);
    out.put_i32((y * 32.0) as i32);
    out.put_i32((z * 32.0) as i32);
    out.put_i8(yaw);
    out.put_i8(pitch);
    out.put_i16(0); // held_item = empty hand
    out.put_u8(0x7F); // metadata terminator
    ConversionResult::Converted(vec![build_payload(V164_S2C_SPAWN_PLAYER, &out)])
}

/// 1.12.2 Entity (no-move heartbeat): `[VarInt entity_id]`.
/// 1.6.4 Entity: `[i32 entity_id]`.
fn s2c_entity(mut body: Bytes) -> ConversionResult {
    let Ok(entity_id) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    out.put_i32(entity_id.0);
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY, &out)])
}

/// 1.12.2 EntityRelativeMove: `[VarInt eid][i16 dx][i16 dy][i16 dz][bool on_ground]`.
/// 1.6.4 EntityRelativeMove: `[i32 eid][i8 dx][i8 dy][i8 dz]`.
/// 1.12.2 deltas are in fp(4096) units, 1.6.4 in fp(32). Convert by /128.
fn s2c_entity_rel_move(mut body: Bytes) -> ConversionResult {
    let Ok(entity_id) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.remaining() < 2 * 3 + 1 {
        return ConversionResult::Passthrough;
    }
    let dx = (body.get_i16() / 128) as i8;
    let dy = (body.get_i16() / 128) as i8;
    let dz = (body.get_i16() / 128) as i8;
    let _og = body.get_u8();
    let mut out = BytesMut::new();
    out.put_i32(entity_id.0);
    out.put_i8(dx);
    out.put_i8(dy);
    out.put_i8(dz);
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY_REL_MOVE, &out)])
}

/// 1.12.2 EntityLook: `[VarInt eid][u8 yaw][u8 pitch][bool on_ground]`.
/// 1.6.4 EntityLook: `[i32 eid][i8 yaw][i8 pitch]`.
fn s2c_entity_look(mut body: Bytes) -> ConversionResult {
    let Ok(entity_id) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.remaining() < 3 {
        return ConversionResult::Passthrough;
    }
    let yaw = body.get_u8() as i8;
    let pitch = body.get_u8() as i8;
    let _og = body.get_u8();
    let mut out = BytesMut::new();
    out.put_i32(entity_id.0);
    out.put_i8(yaw);
    out.put_i8(pitch);
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY_LOOK, &out)])
}

/// 1.12.2 EntityLookAndRelativeMove: `[VarInt eid][i16 dx][i16 dy][i16 dz]`
/// `[u8 yaw][u8 pitch][bool on_ground]`.
/// 1.6.4 EntityLookAndRelativeMove: `[i32 eid][i8 dx][i8 dy][i8 dz][i8 yaw][i8 pitch]`.
fn s2c_entity_look_rel_move(mut body: Bytes) -> ConversionResult {
    let Ok(entity_id) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.remaining() < 2 * 3 + 3 {
        return ConversionResult::Passthrough;
    }
    let dx = (body.get_i16() / 128) as i8;
    let dy = (body.get_i16() / 128) as i8;
    let dz = (body.get_i16() / 128) as i8;
    let yaw = body.get_u8() as i8;
    let pitch = body.get_u8() as i8;
    let _og = body.get_u8();
    let mut out = BytesMut::new();
    out.put_i32(entity_id.0);
    out.put_i8(dx);
    out.put_i8(dy);
    out.put_i8(dz);
    out.put_i8(yaw);
    out.put_i8(pitch);
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY_LOOK_REL_MOVE, &out)])
}

/// 1.12.2 EntityTeleport: `[VarInt eid][f64 x][f64 y][f64 z][u8 yaw][u8 pitch][bool og]`.
/// 1.6.4 EntityTeleport: `[i32 eid][i32 x_fp32][i32 y_fp32][i32 z_fp32][i8 yaw][i8 pitch]`.
fn s2c_entity_teleport(mut body: Bytes) -> ConversionResult {
    let Ok(entity_id) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.remaining() < 8 * 3 + 3 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_f64();
    let y = body.get_f64();
    let z = body.get_f64();
    let yaw = body.get_u8() as i8;
    let pitch = body.get_u8() as i8;
    let _og = body.get_u8();
    let mut out = BytesMut::new();
    out.put_i32(entity_id.0);
    out.put_i32((x * 32.0) as i32);
    out.put_i32((y * 32.0) as i32);
    out.put_i32((z * 32.0) as i32);
    out.put_i8(yaw);
    out.put_i8(pitch);
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY_TELEPORT, &out)])
}

/// 1.12.2 EntityHeadLook: `[VarInt eid][u8 head_yaw]`.
/// 1.6.4 EntityHeadLook: `[i32 eid][i8 head_yaw]`.
fn s2c_entity_head_look(mut body: Bytes) -> ConversionResult {
    let Ok(entity_id) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let head_yaw = body.get_u8() as i8;
    let mut out = BytesMut::new();
    out.put_i32(entity_id.0);
    out.put_i8(head_yaw);
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY_HEAD_LOOK, &out)])
}

/// 1.12.2 DestroyEntities: `[VarInt count][N × VarInt eid]`.
/// 1.6.4 DestroyEntities: `[i8 count][N × i32 eid]`.
fn s2c_destroy_entities(mut body: Bytes) -> ConversionResult {
    let Ok(count) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    if count.0 < 0 || count.0 > 127 {
        return ConversionResult::Drop; // 1.6 can't represent >127 entities
    }
    let mut ids = Vec::with_capacity(count.0 as usize);
    for _ in 0..count.0 {
        let Ok(eid) = VarInt::decode(&mut body) else {
            return ConversionResult::Passthrough;
        };
        ids.push(eid.0);
    }
    let mut out = BytesMut::new();
    out.put_i8(count.0 as i8);
    for id in ids {
        out.put_i32(id);
    }
    ConversionResult::Converted(vec![build_payload(V164_S2C_DESTROY_ENTITIES, &out)])
}

/// 1.12.2 CollectItem: `[VarInt collected_eid][VarInt collector_eid][VarInt count]`.
/// 1.6.4 CollectItem: `[i32 collected_eid][i32 collector_eid]` (no count field).
fn s2c_collect_item(mut body: Bytes) -> ConversionResult {
    let Ok(collected) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let Ok(collector) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let _count = VarInt::decode(&mut body);
    let mut out = BytesMut::new();
    out.put_i32(collected.0);
    out.put_i32(collector.0);
    ConversionResult::Converted(vec![build_payload(V164_S2C_COLLECT_ITEM, &out)])
}

/// 1.12.2 EntityEquipment: `[VarInt eid][VarInt slot][Slot item]`.
/// 1.6.4 EntityEquipment: `[i32 eid][i16 slot][Slot item]`.
/// The Slot serialisation differs structurally — we Drop rather than
/// risk a malformed Slot trailer since the 1.6.4 client refuses
/// partial Slot reads.
fn s2c_entity_equipment(mut body: Bytes) -> ConversionResult {
    let Ok(entity_id) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let Ok(slot) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    // Empty slot marker is safe to forward.
    let mut out = BytesMut::new();
    out.put_i32(entity_id.0);
    out.put_i16(slot.0 as i16);
    out.put_i16(-1); // empty Slot marker
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY_EQUIPMENT, &out)])
}

/// 1.12.2 SetExperience: `[f32 bar][VarInt level][VarInt total_xp]`.
/// 1.6.4 SetExperience (Packet43): `[f32 bar][i16 level][i16 total_xp]`.
fn s2c_set_experience(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let bar = body.get_f32();
    let Ok(level) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let Ok(total) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    out.put_f32(bar);
    out.put_i16(level.0.clamp(0, i16::MAX as i32) as i16);
    out.put_i16(total.0.clamp(0, i16::MAX as i32) as i16);
    ConversionResult::Converted(vec![build_payload(V164_S2C_SET_EXPERIENCE, &out)])
}

/// Pre-netty UCS-2 String writer (u16 BE length + UCS-2 BE chars).
fn encode_legacy_string(s: &str, dst: &mut BytesMut) {
    let units: Vec<u16> = s.encode_utf16().collect();
    dst.put_u16(units.len() as u16);
    for u in units {
        dst.put_u16(u);
    }
}

// ──────────────────────────────────────────────────────────────────────────
// New S2C converters (1.12.2 → 1.6.4)
// ──────────────────────────────────────────────────────────────────────────

fn s2c_spawn_object(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; u8 type; f64 x/y/z; i8 pitch/yaw; i32 objectData; [i16 vx/vy/vz]
    // 1.6.4: i32 eid; i8 type; i32 x_fp32/y_fp32/z_fp32; i8 pitch/yaw; i32 objectData; [i16 vx/vy/vz]
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let Some(typ) = r.u8() else { return ConversionResult::Passthrough; };
    let Some(x) = r.f64() else { return ConversionResult::Passthrough; };
    let Some(y) = r.f64() else { return ConversionResult::Passthrough; };
    let Some(z) = r.f64() else { return ConversionResult::Passthrough; };
    let yaw = r.u8().unwrap_or(0);
    let pitch = r.u8().unwrap_or(0);
    let Some(data) = r.i32() else { return ConversionResult::Passthrough; };

    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_u8(typ);
    out.put_i32((x * 32.0).round() as i32);
    out.put_i32((y * 32.0).round() as i32);
    out.put_i32((z * 32.0).round() as i32);
    out.put_u8(yaw);
    out.put_u8(pitch);
    out.put_i32(data);
    if data != 0 {
        if r.remaining() >= 6 {
            out.put_i16(r.i16().unwrap_or(0));
            out.put_i16(r.i16().unwrap_or(0));
            out.put_i16(r.i16().unwrap_or(0));
        }
    }
    ConversionResult::Converted(vec![build_payload(V164_S2C_SPAWN_OBJECT, &out)])
}

fn s2c_spawn_exp_orb(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; f64 x/y/z; i16 count
    // 1.6.4: i32 eid; i32 x_fp32/y_fp32/z_fp32; i16 count
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let Some(x) = r.f64() else { return ConversionResult::Passthrough; };
    let Some(y) = r.f64() else { return ConversionResult::Passthrough; };
    let Some(z) = r.f64() else { return ConversionResult::Passthrough; };
    let count = r.i16().unwrap_or(0);

    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_i32((x * 32.0).round() as i32);
    out.put_i32((y * 32.0).round() as i32);
    out.put_i32((z * 32.0).round() as i32);
    out.put_i16(count);
    ConversionResult::Converted(vec![build_payload(V164_S2C_SPAWN_EXP_ORB, &out)])
}

fn s2c_spawn_global(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; i8 type; i32 x/y/z
    // 1.6.4: i32 eid; i8 type; i32 x/y/z
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let Some(typ) = r.i8() else { return ConversionResult::Passthrough; };
    let Some(x) = r.i32() else { return ConversionResult::Passthrough; };
    let Some(y) = r.i32() else { return ConversionResult::Passthrough; };
    let Some(z) = r.i32() else { return ConversionResult::Passthrough; };

    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_i8(typ);
    out.put_i32(x);
    out.put_i32(y);
    out.put_i32(z);
    ConversionResult::Converted(vec![build_payload(V164_S2C_SPAWN_GLOBAL, &out)])
}

fn s2c_spawn_mob(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; u8 type; f64 x/y/z; i8 yaw/pitch/headPitch; i16 vx/vy/vz; metadata
    // 1.6.4: i32 eid; u8 type; i32 x_fp32/y_fp32/z_fp32; i8 yaw/pitch/headPitch; i16 vx/vy/vz; metadata
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let Some(typ) = r.u8() else { return ConversionResult::Passthrough; };
    let Some(x) = r.f64() else { return ConversionResult::Passthrough; };
    let Some(y) = r.f64() else { return ConversionResult::Passthrough; };
    let Some(z) = r.f64() else { return ConversionResult::Passthrough; };
    let yaw = r.u8().unwrap_or(0);
    let pitch = r.u8().unwrap_or(0);
    let head_pitch = r.u8().unwrap_or(0);
    let vx = r.i16().unwrap_or(0);
    let vy = r.i16().unwrap_or(0);
    let vz = r.i16().unwrap_or(0);

    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_u8(typ);
    out.put_i32((x * 32.0).round() as i32);
    out.put_i32((y * 32.0).round() as i32);
    out.put_i32((z * 32.0).round() as i32);
    out.put_u8(yaw);
    out.put_u8(pitch);
    out.put_u8(head_pitch);
    out.put_i16(vx);
    out.put_i16(vy);
    out.put_i16(vz);
    out.put_u8(0x7F); // metadata terminator
    ConversionResult::Converted(vec![build_payload(V164_S2C_SPAWN_MOB, &out)])
}

fn s2c_spawn_painting(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; string title; Position packed; u8 direction
    // 1.6.4: i32 eid; UCS-2 title; i32 x; i32 y; i32 z; i32 direction
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let Some(title) = r.string() else { return ConversionResult::Passthrough; };
    let Some(packed) = r.i64() else { return ConversionResult::Passthrough; };
    let direction = r.u8().unwrap_or(0);
    let pos = kojacoord_protocol::types::decode_legacy_position(packed as u64);

    let mut out = BytesMut::new();
    out.put_i32(eid);
    encode_legacy_string(&title, &mut out);
    out.put_i32(pos.x);
    out.put_i32(pos.y);
    out.put_i32(pos.z);
    out.put_i32(direction as i32);
    ConversionResult::Converted(vec![build_payload(V164_S2C_SPAWN_PAINTING, &out)])
}

fn s2c_animation(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; u8 animation
    // 1.6.4: i32 eid; u8 animation
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let Some(anim) = r.u8() else { return ConversionResult::Passthrough; };

    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_u8(anim);
    ConversionResult::Converted(vec![build_payload(V164_S2C_ANIMATION, &out)])
}

fn s2c_statistics(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt count; (string name, VarInt value)[]
    // 1.6.4: i32 count; (UCS-2 name, i32 value)[]
    let mut r = super::safe::Reader::new(body);
    let Some(count) = r.varint() else { return ConversionResult::Passthrough; };
    let mut out = BytesMut::new();
    out.put_i32(count);
    for _ in 0..count {
        let Some(name) = r.string() else { return ConversionResult::Passthrough; };
        let Some(value) = r.varint() else { return ConversionResult::Passthrough; };
        encode_legacy_string(&name, &mut out);
        out.put_i32(value);
    }
    ConversionResult::Converted(vec![build_payload(V164_S2C_STATISTIC, &out)])
}

fn s2c_block_break_anim(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; Position; i8 destroyStage
    // 1.6.4: i32 eid; i32 x; i32 y; i32 z; i8 destroyStage
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let Some(packed) = r.i64() else { return ConversionResult::Passthrough; };
    let stage = r.i8().unwrap_or(0);
    let pos = kojacoord_protocol::types::decode_legacy_position(packed as u64);

    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_i32(pos.x);
    out.put_i32(pos.y);
    out.put_i32(pos.z);
    out.put_i8(stage);
    ConversionResult::Converted(vec![build_payload(V164_S2C_BLOCK_BREAK_ANIM, &out)])
}

fn s2c_tile_entity_data(body: Bytes) -> ConversionResult {
    // 1.12.2: Position; u8 action; NBT data
    // 1.6.4: i32 x; i16 y; i32 z; u8 action; NBT data
    let mut r = super::safe::Reader::new(body);
    let Some(packed) = r.i64() else { return ConversionResult::Passthrough; };
    let Some(action) = r.u8() else { return ConversionResult::Passthrough; };
    let nbt_rest = r.rest();
    let pos = kojacoord_protocol::types::decode_legacy_position(packed as u64);

    let mut out = BytesMut::new();
    out.put_i32(pos.x);
    out.put_i16(pos.y as i16);
    out.put_i32(pos.z);
    out.put_u8(action);
    out.extend_from_slice(&nbt_rest);
    ConversionResult::Converted(vec![build_payload(V164_S2C_TILE_ENTITY_DATA, &out)])
}

fn s2c_block_action(body: Bytes) -> ConversionResult {
    // 1.12.2: Position; u8 byte1; u8 byte2; VarInt blockId
    // 1.6.4: i32 x; i16 y; i32 z; u8 byte1; u8 byte2; i16 blockId
    let mut r = super::safe::Reader::new(body);
    let Some(packed) = r.i64() else { return ConversionResult::Passthrough; };
    let byte1 = r.u8().unwrap_or(0);
    let byte2 = r.u8().unwrap_or(0);
    let block_id = r.varint().unwrap_or(0);
    let pos = kojacoord_protocol::types::decode_legacy_position(packed as u64);

    let mut out = BytesMut::new();
    out.put_i32(pos.x);
    out.put_i16(pos.y as i16);
    out.put_i32(pos.z);
    out.put_u8(byte1);
    out.put_u8(byte2);
    out.put_i16(block_id as i16);
    ConversionResult::Converted(vec![build_payload(V164_S2C_BLOCK_ACTION, &out)])
}

fn s2c_open_window(body: Bytes) -> ConversionResult {
    // 1.12.2: u8 windowId; string inventoryType; string windowTitle; u8 slotCount; [i32 entityId]
    // 1.6.4: u8 windowId; u8 inventoryType; UCS-2 windowTitle; u8 slotCount; [u8 useProvidedTitle; i32 entityId]
    let mut r = super::safe::Reader::new(body);
    let Some(wid) = r.u8() else { return ConversionResult::Passthrough; };
    let Some(inv_type_str) = r.string() else { return ConversionResult::Passthrough; };
    let Some(title) = r.string() else { return ConversionResult::Passthrough; };
    let slot_count = r.u8().unwrap_or(0);
    let inv_type_id: u8 = match inv_type_str.as_str() {
        "minecraft:chest" => 0,
        "minecraft:crafting_table" => 1,
        "minecraft:furnace" => 2,
        "minecraft:dispenser" => 3,
        "minecraft:enchanting_table" => 4,
        "minecraft:brewing_stand" => 5,
        "minecraft:villager" => 6,
        "minecraft:beacon" => 7,
        "minecraft:anvil" => 8,
        "minecraft:hopper" => 9,
        "minecraft:dropper" => 10,
        "EntityHorse" => 11,
        _ => 0,
    };

    let mut out = BytesMut::new();
    out.put_u8(wid);
    out.put_u8(inv_type_id);
    encode_legacy_string(&title, &mut out);
    out.put_u8(slot_count);
    if inv_type_id == 11 {
        out.put_u8(1); // useProvidedTitle = true
        let eid = r.i32().unwrap_or(0);
        out.put_i32(eid);
    }
    ConversionResult::Converted(vec![build_payload(V164_S2C_OPEN_WINDOW, &out)])
}

fn s2c_close_window(body: Bytes) -> ConversionResult {
    // 1.12.2: u8 windowId. 1.6.4: u8 windowId.
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    ConversionResult::Converted(vec![build_payload(V164_S2C_CLOSE_WINDOW, &body)])
}

fn s2c_set_slot(body: Bytes) -> ConversionResult {
    // 1.12.2: i8 windowId; i16 slot; Slot
    // 1.6.4: i8 windowId; i16 slot; Slot (legacy format)
    // Slot format differs — we forward the header and emit an empty slot to avoid garbage.
    let mut r = super::safe::Reader::new(body);
    let Some(wid) = r.i8() else { return ConversionResult::Passthrough; };
    let Some(slot) = r.i16() else { return ConversionResult::Passthrough; };

    let mut out = BytesMut::new();
    out.put_i8(wid);
    out.put_i16(slot);
    out.put_i16(-1); // empty slot marker
    ConversionResult::Converted(vec![build_payload(V164_S2C_SET_SLOT, &out)])
}

fn s2c_window_items(body: Bytes) -> ConversionResult {
    // 1.12.2: u8 windowId; i16 count; Slot[]
    // 1.6.4: u8 windowId; i16 count; Slot[] (legacy format)
    // Slot format differs structurally — emit empty slots to avoid garbage.
    let mut r = super::safe::Reader::new(body);
    let Some(wid) = r.u8() else { return ConversionResult::Passthrough; };
    let Some(count) = r.i16() else { return ConversionResult::Passthrough; };

    let mut out = BytesMut::new();
    out.put_u8(wid);
    out.put_i16(count);
    for _ in 0..count {
        out.put_i16(-1); // empty slot
    }
    ConversionResult::Converted(vec![build_payload(V164_S2C_WINDOW_ITEMS, &out)])
}

fn s2c_window_property(body: Bytes) -> ConversionResult {
    // 1.12.2: u8 windowId; i16 property; i16 value
    // 1.6.4: u8 windowId; i16 property; i16 value
    if body.remaining() < 5 {
        return ConversionResult::Passthrough;
    }
    ConversionResult::Converted(vec![build_payload(V164_S2C_WINDOW_PROPERTY, &body)])
}

fn s2c_confirm_transaction(body: Bytes) -> ConversionResult {
    // 1.12.2: i8 windowId; i16 action; bool accepted
    // 1.6.4: i8 windowId; i16 action; bool accepted
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    ConversionResult::Converted(vec![build_payload(V164_S2C_CONFIRM_TRANSACTION, &body)])
}

fn s2c_open_sign_editor(body: Bytes) -> ConversionResult {
    // 1.12.2: Position. 1.6.4: i32 x; i32 y; i32 z
    let mut r = super::safe::Reader::new(body);
    let Some(packed) = r.i64() else { return ConversionResult::Passthrough; };
    let pos = kojacoord_protocol::types::decode_legacy_position(packed as u64);
    let mut out = BytesMut::new();
    out.put_i32(pos.x);
    out.put_i32(pos.y);
    out.put_i32(pos.z);
    ConversionResult::Converted(vec![build_payload(V164_S2C_OPEN_SIGN_EDITOR, &out)])
}

fn s2c_tab_complete(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt count; string[]
    // 1.6.4: UCS-2 string (NUL-separated)
    let mut r = super::safe::Reader::new(body);
    let Some(count) = r.varint() else { return ConversionResult::Passthrough; };
    let mut parts: Vec<String> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Some(s) = r.string() else { return ConversionResult::Passthrough; };
        parts.push(s);
    }
    let joined = parts.join("\0");
    let mut out = BytesMut::new();
    encode_legacy_string(&joined, &mut out);
    ConversionResult::Converted(vec![build_payload(V164_S2C_TAB_COMPLETE, &out)])
}

fn s2c_scoreboard_obj(body: Bytes) -> ConversionResult {
    // 1.12.2: string name; i8 mode; [string displayName; string type]
    // 1.6.4: UCS-2 name; i8 mode; [UCS-2 displayName; UCS-2 type]
    let mut r = super::safe::Reader::new(body);
    let Some(name) = r.string() else { return ConversionResult::Passthrough; };
    let mode = r.u8().unwrap_or(0);
    let mut out = BytesMut::new();
    encode_legacy_string(&name, &mut out);
    out.put_u8(mode);
    if mode == 0 || mode == 2 {
        let Some(display) = r.string() else { return ConversionResult::Passthrough; };
        let rest_type = r.string().unwrap_or_else(|| "integer".to_owned());
        encode_legacy_string(&display, &mut out);
        encode_legacy_string(&rest_type, &mut out);
    }
    ConversionResult::Converted(vec![build_payload(V164_S2C_SCOREBOARD_OBJ, &out)])
}

fn s2c_update_score(body: Bytes) -> ConversionResult {
    // 1.12.2: string name; i8 action; string objective; VarInt value
    // 1.6.4: UCS-2 name; i8 action; UCS-2 objective; i32 value
    let mut r = super::safe::Reader::new(body);
    let Some(name) = r.string() else { return ConversionResult::Passthrough; };
    let action = r.u8().unwrap_or(0);
    let Some(obj) = r.string() else { return ConversionResult::Passthrough; };
    let value = r.varint().unwrap_or(0);
    let mut out = BytesMut::new();
    encode_legacy_string(&name, &mut out);
    out.put_u8(action);
    encode_legacy_string(&obj, &mut out);
    out.put_i32(value);
    ConversionResult::Converted(vec![build_payload(V164_S2C_UPDATE_SCORE, &out)])
}

fn s2c_display_scoreboard(body: Bytes) -> ConversionResult {
    // 1.12.2: i8 slot; string name
    // 1.6.4: i8 slot; UCS-2 name
    let mut r = super::safe::Reader::new(body);
    let slot = r.i8().unwrap_or(0);
    let Some(name) = r.string() else { return ConversionResult::Passthrough; };
    let mut out = BytesMut::new();
    out.put_i8(slot);
    encode_legacy_string(&name, &mut out);
    ConversionResult::Converted(vec![build_payload(V164_S2C_DISPLAY_SCOREBOARD, &out)])
}

fn s2c_teams(body: Bytes) -> ConversionResult {
    // 1.12.2: string name; i8 mode; [string displayName; string prefix; string suffix; i8 flags; string nameTagVisibility; string collisionRule; i8 color]
    // 1.6.4: UCS-2 name; i8 mode; [UCS-2 displayName; UCS-2 prefix; UCS-2 suffix; i8 flags; i8 color; i8 friendlyFire]
    // Team format is complex and version-dependent — best-effort passthrough.
    let mut r = super::safe::Reader::new(body);
    let Some(name) = r.string() else { return ConversionResult::Passthrough; };
    let mode = r.u8().unwrap_or(0);
    let mut out = BytesMut::new();
    encode_legacy_string(&name, &mut out);
    out.put_u8(mode);
    if mode == 0 || mode == 2 {
        let display = r.string().unwrap_or_default();
        let prefix = r.string().unwrap_or_default();
        let suffix = r.string().unwrap_or_default();
        let flags = r.u8().unwrap_or(0);
        r.string(); // nameTagVisibility — skip
        r.string(); // collisionRule — skip
        let color = r.u8().unwrap_or(0);
        encode_legacy_string(&display, &mut out);
        encode_legacy_string(&prefix, &mut out);
        encode_legacy_string(&suffix, &mut out);
        out.put_u8(flags);
        out.put_u8(color);
        out.put_u8(flags); // friendlyFire (reuse flags byte)
    }
    if mode == 0 || mode == 3 || mode == 4 {
        let count = r.varint().unwrap_or(0);
        VarInt(count).encode(&mut out).unwrap();
        for _ in 0..count {
            let entry = r.string().unwrap_or_default();
            encode_legacy_string(&entry, &mut out);
        }
    }
    ConversionResult::Converted(vec![build_payload(V164_S2C_TEAMS, &out)])
}

fn s2c_entity_status(body: Bytes) -> ConversionResult {
    // 1.12.2: i32 eid; i8 status. 1.6.4: i32 eid; i8 status.
    if body.remaining() < 5 { return ConversionResult::Passthrough; }
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY_STATUS, &body)])
}

fn s2c_attach_entity(body: Bytes) -> ConversionResult {
    // 1.12.2: i32 eid; i32 vehicleId; bool leash
    // 1.6.4: i32 eid; i32 vehicleId; bool leash
    if body.remaining() < 9 { return ConversionResult::Passthrough; }
    ConversionResult::Converted(vec![build_payload(V164_S2C_ATTACH_ENTITY, &body)])
}

fn s2c_entity_metadata(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; metadata. 1.6.4: i32 eid; metadata.
    // Metadata format is incompatible — stub terminator.
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_u8(0x7F); // metadata terminator
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY_METADATA, &out)])
}

fn s2c_entity_effect(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; i8 effectId; i8 amplifier; VarInt duration; bool hideParticles
    // 1.6.4: i32 eid; i8 effectId; i8 amplifier; i16 duration
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let effect_id = r.i8().unwrap_or(0);
    let amplifier = r.i8().unwrap_or(0);
    let duration = r.varint().unwrap_or(0);
    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_i8(effect_id);
    out.put_i8(amplifier);
    out.put_i16(duration.clamp(0, i16::MAX as i32) as i16);
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY_EFFECT, &out)])
}

fn s2c_remove_entity_effect(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; i8 effectId. 1.6.4: i32 eid; i8 effectId.
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let effect_id = r.i8().unwrap_or(0);
    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_i8(effect_id);
    ConversionResult::Converted(vec![build_payload(V164_S2C_REMOVE_ENTITY_EFFECT, &out)])
}

fn s2c_entity_properties(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; i32 count; (string key; f64 value; VarInt modCount; (UUID f64 i8)[])[]
    // 1.6.4: i32 eid; i32 count; (string key; f64 value; i16 modCount; (UUID f64 i8)[])[]
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let Some(prop_count) = r.i32() else { return ConversionResult::Passthrough; };
    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_i32(prop_count);
    for _ in 0..prop_count {
        let Some(key) = r.string() else { return ConversionResult::Passthrough; };
        let Some(value) = r.f64() else { return ConversionResult::Passthrough; };
        let mod_count = r.varint().unwrap_or(0);
        key.encode(&mut out).unwrap();
        out.put_f64(value);
        out.put_i16(mod_count.clamp(0, i16::MAX as i32) as i16);
        for _ in 0..mod_count {
            let msb = r.i64().unwrap_or(0);
            let lsb = r.i64().unwrap_or(0);
            let amount = r.f64().unwrap_or(0.0);
            let op = r.i8().unwrap_or(0);
            out.put_i64(msb);
            out.put_i64(lsb);
            out.put_f64(amount);
            out.put_i8(op);
        }
    }
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY_PROPERTIES, &out)])
}

fn s2c_entity_velocity(body: Bytes) -> ConversionResult {
    // 1.12.2: VarInt eid; i16 vx/vy/vz. 1.6.4: i32 eid; i16 vx/vy/vz.
    let mut r = super::safe::Reader::new(body);
    let Some(eid) = r.varint() else { return ConversionResult::Passthrough; };
    let vx = r.i16().unwrap_or(0);
    let vy = r.i16().unwrap_or(0);
    let vz = r.i16().unwrap_or(0);
    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_i16(vx);
    out.put_i16(vy);
    out.put_i16(vz);
    ConversionResult::Converted(vec![build_payload(V164_S2C_ENTITY_VELOCITY, &out)])
}

fn s2c_effect(body: Bytes) -> ConversionResult {
    // 1.12.2: i32 effectId; Position; i32 data; bool global
    // 1.6.4: i32 effectId; i32 x; i32 y; i32 z; i32 data; bool global
    let mut r = super::safe::Reader::new(body);
    let Some(effect_id) = r.i32() else { return ConversionResult::Passthrough; };
    let Some(packed) = r.i64() else { return ConversionResult::Passthrough; };
    let data = r.i32().unwrap_or(0);
    let global = r.u8().unwrap_or(0);
    let pos = kojacoord_protocol::types::decode_legacy_position(packed as u64);

    let mut out = BytesMut::new();
    out.put_i32(effect_id);
    out.put_i32(pos.x);
    out.put_i32(pos.y);
    out.put_i32(pos.z);
    out.put_i32(data);
    out.put_u8(global);
    ConversionResult::Converted(vec![build_payload(V164_S2C_EFFECT, &out)])
}

fn s2c_named_sound(_body: Bytes) -> ConversionResult {
    // 1.12.2 and 1.6.4 have very different named sound formats.
    // Dropping rather than risking malformed output.
    tracing::debug!(target: "converter", "1.12.2→1.6.4: named sound effect dropped (format differs)");
    ConversionResult::Drop
}

fn s2c_explosion(body: Bytes) -> ConversionResult {
    // 1.12.2: f32 x/y/z; f32 radius; VarInt count; (i8,i8,i8)[]; f32 motionX/Y/Z
    // 1.6.4: f32 x/y/z; f32 radius; i32 count; (i8,i8,i8)[]; f32 motionX/Y/Z
    // Very similar — only count type differs (VarInt vs i32).
    let mut r = super::safe::Reader::new(body);
    let Some(x) = r.f32() else { return ConversionResult::Passthrough; };
    let Some(y) = r.f32() else { return ConversionResult::Passthrough; };
    let Some(z) = r.f32() else { return ConversionResult::Passthrough; };
    let Some(radius) = r.f32() else { return ConversionResult::Passthrough; };
    let Some(count) = r.varint() else { return ConversionResult::Passthrough; };
    let mut out = BytesMut::new();
    out.put_f32(x);
    out.put_f32(y);
    out.put_f32(z);
    out.put_f32(radius);
    out.put_i32(count);
    for _ in 0..count {
        let dx = r.i8().unwrap_or(0);
        let dy = r.i8().unwrap_or(0);
        let dz = r.i8().unwrap_or(0);
        out.put_i8(dx);
        out.put_i8(dy);
        out.put_i8(dz);
    }
    let mx = r.f32().unwrap_or(0.0);
    let my = r.f32().unwrap_or(0.0);
    let mz = r.f32().unwrap_or(0.0);
    out.put_f32(mx);
    out.put_f32(my);
    out.put_f32(mz);
    ConversionResult::Converted(vec![build_payload(V164_S2C_EXPLOSION, &out)])
}

fn s2c_game_state(body: Bytes) -> ConversionResult {
    // 1.12.2: u8 reason; f32 value. 1.6.4: i8 reason; f32 value.
    if body.remaining() < 5 { return ConversionResult::Passthrough; }
    let out = BytesMut::from(body.as_ref());
    ConversionResult::Converted(vec![build_payload(V164_S2C_GAME_STATE, &out)])
}

// ──────────────────────────────────────────────────────────────────────────
// New C2S converters (1.12.2 → 1.6.4)
// ──────────────────────────────────────────────────────────────────────────

fn c2s_tab_complete(mut body: Bytes) -> ConversionResult {
    // 1.12.2: string text; bool assumeCommand; [bool hasPos; Position]
    // 1.6.4: UCS-2 text
    let Ok(text) = String::decode(&mut body) else { return ConversionResult::Passthrough; };
    let mut out = BytesMut::new();
    encode_legacy_string(&text, &mut out);
    ConversionResult::Converted(vec![build_payload(V164_C2S_TAB_COMPLETE, &out)])
}

fn c2s_confirm_transaction(body: Bytes) -> ConversionResult {
    // 1.12.2: i8 windowId; i16 action; bool accepted. 1.6.4: same.
    if body.remaining() < 4 { return ConversionResult::Passthrough; }
    ConversionResult::Converted(vec![build_payload(V164_C2S_CONFIRM_TRANSACTION, &body)])
}

fn c2s_enchant_item(body: Bytes) -> ConversionResult {
    // 1.12.2: i8 windowId; i8 enchantment. 1.6.4: same.
    if body.remaining() < 2 { return ConversionResult::Passthrough; }
    ConversionResult::Converted(vec![build_payload(V164_C2S_ENCHANT_ITEM, &body)])
}

fn c2s_window_click(body: Bytes) -> ConversionResult {
    // 1.12.2: u8 windowId; i16 slot; u8 button; i16 action; VarInt mode; Slot
    // 1.6.4: i8 windowId; i16 slot; i8 button; i16 action; i8 mode; Slot (legacy)
    // Slot format differs structurally — we emit an empty slot.
    let mut r = super::safe::Reader::new(body);
    let Some(wid) = r.u8() else { return ConversionResult::Passthrough; };
    let Some(slot) = r.i16() else { return ConversionResult::Passthrough; };
    let button = r.u8().unwrap_or(0);
    let action = r.i16().unwrap_or(0);
    let mode = r.varint().unwrap_or(0);
    let mut out = BytesMut::new();
    out.put_i8(wid as i8);
    out.put_i16(slot);
    out.put_i8(button as i8);
    out.put_i16(action);
    out.put_i8(mode as i8);
    out.put_i16(-1); // empty slot
    ConversionResult::Converted(vec![build_payload(V164_C2S_WINDOW_CLICK, &out)])
}

fn c2s_creative_inv(body: Bytes) -> ConversionResult {
    // 1.12.2: i16 slot; Slot. 1.6.4: i16 slot; Slot (legacy).
    // Emit empty slot for safety.
    let mut r = super::safe::Reader::new(body);
    let Some(slot) = r.i16() else { return ConversionResult::Passthrough; };
    let mut out = BytesMut::new();
    out.put_i16(slot);
    out.put_i16(-1); // empty slot
    ConversionResult::Converted(vec![build_payload(V164_C2S_CREATIVE_INV, &out)])
}

fn c2s_steer_vehicle(mut body: Bytes) -> ConversionResult {
    // 1.12.2: f32 sideways; f32 forward; u8 flags. 1.6.4: f32 sideways; f32 forward; bool jump; bool unmount.
    if body.remaining() < 9 { return ConversionResult::Passthrough; }
    let sideways = body.get_f32();
    let forward = body.get_f32();
    let flags = body.get_u8();
    let jump = (flags & 0x02) != 0;
    let unmount = (flags & 0x01) != 0;

    let mut out = BytesMut::with_capacity(10);
    out.put_f32(sideways);
    out.put_f32(forward);
    out.put_u8(jump as u8);
    out.put_u8(unmount as u8);
    ConversionResult::Converted(vec![build_payload(V164_C2S_STEER_VEHICLE, &out)])
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
