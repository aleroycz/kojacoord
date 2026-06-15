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
const V164_S2C_ENTITY_TELEPORT: u8 = 0x22; // Packet34EntityTeleport
const V164_S2C_ENTITY_REL_MOVE: u8 = 0x15; // Packet21EntityRelativeMove
const V164_S2C_ENTITY: u8 = 0x1E; // Packet30Entity
const V164_S2C_BLOCK_CHANGE: u8 = 0x35; // Packet53BlockChange
const V164_S2C_SET_SLOT: u8 = 0x67; // Packet103SetSlot
const V164_S2C_WINDOW_ITEMS: u8 = 0x68; // Packet104WindowItems
/// **Important**: the existing name is misleading — `0x1C` is actually
/// `Packet28EntityVelocity` per the Notchian pre-netty table. Kept as
/// `V164_S2C_ENTITY_EQUIPMENT` to avoid breaking callers; the real
/// EntityEquipment packet is `Packet5EntityEquipment` (id 0x05).
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
const V164_S2C_LOGIN_REQUEST: u8 = 0x01; // Packet1Login
const V164_S2C_ENTITY_EQUIPMENT_REAL: u8 = 0x05; // Packet5PlayerInventory
const V164_S2C_RESPAWN: u8 = 0x09; // Packet9Respawn
const V164_S2C_USE_BED: u8 = 0x11; // Packet17Sleep
const V164_S2C_ANIMATION: u8 = 0x12; // Packet18Animation
const V164_S2C_SPAWN_OBJECT: u8 = 0x17; // Packet23VehicleSpawn
const V164_S2C_SPAWN_MOB: u8 = 0x18; // Packet24MobSpawn
const V164_S2C_SPAWN_PAINTING: u8 = 0x19; // Packet25EntityPainting
const V164_S2C_SPAWN_EXP_ORB: u8 = 0x1A; // Packet26EntityExpOrb
const V164_S2C_ENTITY_VELOCITY: u8 = 0x1C; // Packet28EntityVelocity
const V164_S2C_ENTITY_LOOK: u8 = 0x20; // Packet32EntityLook
const V164_S2C_ENTITY_LOOK_REL_MOVE: u8 = 0x21; // Packet33RelEntityMoveLook
const V164_S2C_ENTITY_STATUS: u8 = 0x26; // Packet38EntityStatus
const V164_S2C_ATTACH_ENTITY: u8 = 0x27; // Packet39AttachEntity
const V164_S2C_ENTITY_METADATA: u8 = 0x28; // Packet40EntityMetadata
const V164_S2C_ENTITY_EFFECT: u8 = 0x29; // Packet41EntityEffect
const V164_S2C_REMOVE_ENTITY_EFFECT: u8 = 0x2A; // Packet42RemoveEntityEffect
const V164_S2C_ENTITY_PROPERTIES: u8 = 0x2C; // Packet44UpdateAttributes
const V164_S2C_MULTI_BLOCK_CHANGE: u8 = 0x34; // Packet52MultiBlockChange
const V164_S2C_BLOCK_ACTION: u8 = 0x36; // Packet54PlayNoteBlock
const V164_S2C_BLOCK_BREAK_ANIMATION: u8 = 0x37; // Packet55BlockDestroy
const V164_S2C_EXPLOSION: u8 = 0x3C; // Packet60Explosion
const V164_S2C_EFFECT: u8 = 0x3D; // Packet61DoorChange
const V164_S2C_NAMED_SOUND: u8 = 0x3E; // Packet62LevelSound
const V164_S2C_PARTICLE: u8 = 0x3F; // Packet63WorldParticles
const V164_S2C_GAME_STATE: u8 = 0x46; // Packet70GameEvent
const V164_S2C_SPAWN_GLOBAL_ENTITY: u8 = 0x47; // Packet71Weather
const V164_S2C_OPEN_WINDOW: u8 = 0x64; // Packet100OpenWindow
const V164_S2C_CLOSE_WINDOW: u8 = 0x65; // Packet101CloseWindow
const V164_S2C_UPDATE_WINDOW_PROPERTY: u8 = 0x69; // Packet105UpdateProgressbar
const V164_S2C_CONFIRM_TRANSACTION: u8 = 0x6A; // Packet106Transaction
const V164_S2C_ITEM_DATA: u8 = 0x83; // Packet131MapData
const V164_S2C_UPDATE_TILE_ENTITY: u8 = 0x84; // Packet132TileEntityData
const V164_S2C_STATISTIC: u8 = 0xC8; // Packet200Statistic
const V164_S2C_PLAYER_LIST_ITEM: u8 = 0xC9; // Packet201PlayerInfo
const V164_S2C_SCOREBOARD_OBJECTIVE: u8 = 0xCE; // Packet206SetObjective
const V164_S2C_UPDATE_SCORE: u8 = 0xCF; // Packet207SetScore
const V164_S2C_DISPLAY_SCOREBOARD: u8 = 0xD0; // Packet208SetDisplayObjective
const V164_S2C_TEAMS: u8 = 0xD1; // Packet209SetPlayerTeam

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
const V112_S2C_ENTITY_VELOCITY: u8 = 0x3E;
const V112_S2C_UPDATE_HEALTH: u8 = 0x41;
const V112_S2C_SPAWN_POSITION: u8 = 0x46;
const V112_S2C_TIME_UPDATE: u8 = 0x47;
const V112_S2C_COLLECT_ITEM: u8 = 0x4B;
const V112_S2C_LOGIN: u8 = 0x23; // JoinGame
const V112_S2C_RESPAWN: u8 = 0x35;
const V112_S2C_SPAWN_OBJECT: u8 = 0x00; // SpawnObject
const V112_S2C_SPAWN_MOB: u8 = 0x03; // SpawnMob / spawn_entity_living
const V112_S2C_SPAWN_PAINTING: u8 = 0x04; // SpawnPainting
const V112_S2C_SPAWN_EXP_ORB: u8 = 0x01; // SpawnExperienceOrb
const V112_S2C_ENTITY_LOOK: u8 = 0x28;
const V112_S2C_ENTITY_LOOK_REL_MOVE: u8 = 0x27;
const V112_S2C_ENTITY_STATUS: u8 = 0x1B;
const V112_S2C_ATTACH_ENTITY: u8 = 0x3D;
const V112_S2C_ENTITY_METADATA: u8 = 0x3C;
const V112_S2C_ENTITY_EFFECT: u8 = 0x4F;
const V112_S2C_REMOVE_ENTITY_EFFECT: u8 = 0x33;
const V112_S2C_ENTITY_PROPERTIES: u8 = 0x4E;
#[allow(dead_code)]
const V112_S2C_MULTI_BLOCK_CHANGE: u8 = 0x10;
const V112_S2C_BLOCK_ACTION: u8 = 0x0A;
const V112_S2C_BLOCK_BREAK_ANIMATION: u8 = 0x08;
const V112_S2C_EXPLOSION: u8 = 0x1C;
const V112_S2C_EFFECT: u8 = 0x21; // world_event
const V112_S2C_NAMED_SOUND: u8 = 0x19;
#[allow(dead_code)]
const V112_S2C_PARTICLE: u8 = 0x22;
const V112_S2C_GAME_STATE: u8 = 0x1E;
const V112_S2C_SPAWN_GLOBAL_ENTITY: u8 = 0x02; // spawn_entity_weather
const V112_S2C_OPEN_WINDOW: u8 = 0x13;
const V112_S2C_CLOSE_WINDOW: u8 = 0x12;
const V112_S2C_UPDATE_WINDOW_PROPERTY: u8 = 0x15;
const V112_S2C_CONFIRM_TRANSACTION: u8 = 0x11;
const V112_S2C_PLAYER_LIST_ITEM: u8 = 0x2E;
const V112_S2C_SCOREBOARD_OBJECTIVE: u8 = 0x42;
const V112_S2C_UPDATE_SCORE: u8 = 0x45;
const V112_S2C_DISPLAY_SCOREBOARD: u8 = 0x3B;
#[allow(dead_code)]
const V112_S2C_TEAMS: u8 = 0x44;
const V112_S2C_ANIMATION: u8 = 0x06;
const V112_S2C_STATISTIC: u8 = 0x07;
const V112_S2C_TILE_ENTITY_DATA: u8 = 0x09;

pub fn convert_s2c(payload: Bytes) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    match id {
        V164_S2C_KEEP_ALIVE => s2c_keep_alive(body),
        V164_S2C_LOGIN_REQUEST => s2c_login_request(body),
        V164_S2C_CHAT => s2c_chat(body),
        V164_S2C_RESPAWN => s2c_respawn(body),
        V164_S2C_ENTITY_EQUIPMENT_REAL => s2c_entity_equipment_real(body),
        V164_S2C_PLAYER_POS_LOOK => s2c_player_pos_look(body),
        V164_S2C_SPAWN_PLAYER => s2c_spawn_player(body),
        V164_S2C_USE_BED => s2c_use_bed(body),
        V164_S2C_ANIMATION => s2c_animation(body),
        V164_S2C_SPAWN_OBJECT => s2c_spawn_object(body),
        V164_S2C_SPAWN_MOB => s2c_spawn_mob(body),
        V164_S2C_SPAWN_PAINTING => s2c_spawn_painting(body),
        V164_S2C_SPAWN_EXP_ORB => s2c_spawn_exp_orb(body),
        V164_S2C_ENTITY_TELEPORT => s2c_entity_teleport(body),
        V164_S2C_ENTITY_REL_MOVE => s2c_entity_rel_move(body),
        V164_S2C_ENTITY => s2c_entity(body),
        V164_S2C_ENTITY_VELOCITY => s2c_entity_velocity(body),
        V164_S2C_ENTITY_LOOK => s2c_entity_look(body),
        V164_S2C_ENTITY_LOOK_REL_MOVE => s2c_entity_look_rel_move(body),
        V164_S2C_ENTITY_STATUS => s2c_entity_status(body),
        V164_S2C_ATTACH_ENTITY => s2c_attach_entity(body),
        V164_S2C_ENTITY_METADATA => s2c_entity_metadata(body),
        V164_S2C_ENTITY_EFFECT => s2c_entity_effect(body),
        V164_S2C_REMOVE_ENTITY_EFFECT => s2c_remove_entity_effect(body),
        V164_S2C_ENTITY_PROPERTIES => s2c_entity_properties(body),
        V164_S2C_BLOCK_CHANGE => s2c_block_change(body),
        V164_S2C_MULTI_BLOCK_CHANGE => s2c_multi_block_change(body),
        V164_S2C_BLOCK_ACTION => s2c_block_action(body),
        V164_S2C_BLOCK_BREAK_ANIMATION => s2c_block_break_animation(body),
        V164_S2C_EXPLOSION => s2c_explosion(body),
        V164_S2C_EFFECT => s2c_effect(body),
        V164_S2C_NAMED_SOUND => s2c_named_sound(body),
        V164_S2C_PARTICLE => s2c_particle(body),
        V164_S2C_GAME_STATE => s2c_game_state(body),
        V164_S2C_SPAWN_GLOBAL_ENTITY => s2c_spawn_global_entity(body),
        V164_S2C_SET_SLOT => s2c_set_slot(body),
        V164_S2C_WINDOW_ITEMS => s2c_window_items(body),
        V164_S2C_OPEN_WINDOW => s2c_open_window(body),
        V164_S2C_CLOSE_WINDOW => s2c_close_window_s2c(body),
        V164_S2C_UPDATE_WINDOW_PROPERTY => s2c_update_window_property(body),
        V164_S2C_CONFIRM_TRANSACTION => s2c_confirm_transaction_s2c(body),
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
        V164_S2C_UPDATE_TILE_ENTITY => s2c_update_tile_entity(body),
        V164_S2C_ITEM_DATA => s2c_item_data(body),
        V164_S2C_STATISTIC => s2c_statistic(body),
        V164_S2C_PLAYER_LIST_ITEM => s2c_player_list_item(body),
        V164_S2C_SCOREBOARD_OBJECTIVE => s2c_scoreboard_objective(body),
        V164_S2C_UPDATE_SCORE => s2c_update_score(body),
        V164_S2C_DISPLAY_SCOREBOARD => s2c_display_scoreboard(body),
        V164_S2C_TEAMS => s2c_teams(body),
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

// ── New batch: remaining 1.6.4 S2C packets ──────────────────────────

/// 1.6.4 LoginRequest (Packet1Login, 0x01):
///   `[i32 entity_id][UCS-2 level_type][i8 gamemode][i8 dimension][i8 difficulty][u8 world_height][u8 max_players]`.
/// 1.12.2 JoinGame (0x23):
///   `[i32 entity_id][u8 gamemode][i32 dimension][u8 difficulty][u8 max_players][String level_type][bool reduced_debug]`.
fn s2c_login_request(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 2 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body.get_i32();
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let str_len = body.get_u16() as usize;
    if body.remaining() < str_len * 2 + 5 {
        return ConversionResult::Passthrough;
    }
    let mut chars = Vec::with_capacity(str_len);
    for _ in 0..str_len {
        chars.push(body.get_u16());
    }
    let level_type = String::from_utf16_lossy(&chars);
    let gamemode = body.get_i8();
    let dimension = body.get_i8();
    let difficulty = body.get_i8();
    let _world_height = body.get_u8();
    let max_players = body.get_u8();

    let mut out = BytesMut::new();
    out.put_i32(entity_id);
    out.put_u8(gamemode as u8);
    out.put_i32(dimension as i32);
    out.put_u8(difficulty as u8);
    out.put_u8(max_players);
    VarInt(level_type.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(level_type.as_bytes());
    out.put_u8(0); // reduced_debug = false
    ConversionResult::Converted(vec![build_payload(V112_S2C_LOGIN, &out)])
}

/// 1.6.4 Respawn (Packet9, 0x09):
///   `[i32 dimension][i8 difficulty][i8 gamemode][i16 world_height][UCS-2 level_type]`.
/// 1.12.2 Respawn (0x35):
///   `[i32 dimension][u8 difficulty][u8 gamemode][String level_type]`.
fn s2c_respawn(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 1 + 1 + 2 {
        return ConversionResult::Passthrough;
    }
    let dimension = body.get_i32();
    let difficulty = body.get_i8();
    let gamemode = body.get_i8();
    let _world_height = body.get_i16();
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let str_len = body.get_u16() as usize;
    if body.remaining() < str_len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut chars = Vec::with_capacity(str_len);
    for _ in 0..str_len {
        chars.push(body.get_u16());
    }
    let level_type = String::from_utf16_lossy(&chars);
    let mut out = BytesMut::new();
    out.put_i32(dimension);
    out.put_u8(difficulty as u8);
    out.put_u8(gamemode as u8);
    VarInt(level_type.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(level_type.as_bytes());
    ConversionResult::Converted(vec![build_payload(V112_S2C_RESPAWN, &out)])
}

/// 1.6.4 Packet5PlayerInventory (0x05):
///   `[i32 entity_id][i16 slot][Slot item]`.
/// 1.12.2 EntityEquipment (0x3F):
///   `[VarInt entity_id][VarInt slot][Slot item]`.
fn s2c_entity_equipment_real(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 2 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body.get_i32();
    let slot = body.get_i16();
    let mut out = BytesMut::new();
    VarInt(entity_id).encode(&mut out).unwrap();
    VarInt(slot as i32).encode(&mut out).unwrap();
    out.put_u8(0); // empty Slot marker
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_EQUIPMENT, &out)])
}

/// 1.6.4 UseBed (Packet17, 0x11):
///   `[i32 entity_id][i8 unknown][i32 x][i8 y][i32 z]`.
/// No 1.12.2 equivalent — drop silently.
fn s2c_use_bed(_body: Bytes) -> ConversionResult {
    ConversionResult::Drop
}

/// 1.6.4 Animation S2C (Packet18, 0x12):
///   `[i32 entity_id][i8 animation]`.
/// 1.12.2 Animation S2C (0x06):
///   `[VarInt entity_id][u8 animation]` (unsigned animation id).
fn s2c_animation(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 5 {
        return ConversionResult::Passthrough;
    }
    let entity_id = body.get_i32();
    let animation = body.get_u8();
    let mut out = BytesMut::new();
    VarInt(entity_id).encode(&mut out).unwrap();
    out.put_u8(animation);
    ConversionResult::Converted(vec![build_payload(V112_S2C_ANIMATION, &out)])
}

/// 1.6.4 SpawnObject/Vehicle (Packet23, 0x17):
///   `[i32 eid][i8 type][i32 x][i32 y][i32 z][i8 pitch][i8 yaw][i32 thrower_eid]`
///   + if thrower_eid > 0: `[i16 speed_x][i16 speed_y][i16 speed_z]`.
/// 1.12.2 SpawnObject (0x00):
///   `[VarInt eid][u8 type][f64 x][f64 y][f64 z][i8 pitch][i8 yaw][i32 data]`
///   + if data > 0: `[i16 speed_x][i16 speed_y][i16 speed_z]`.
fn s2c_spawn_object(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 1 + 4 + 4 + 4 + 1 + 1 + 4 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let obj_type = body.get_i8();
    let x = body.get_i32() as f64 / 32.0;
    let y = body.get_i32() as f64 / 32.0;
    let z = body.get_i32() as f64 / 32.0;
    let pitch = body.get_i8();
    let yaw = body.get_i8();
    let thrower_eid = body.get_i32();
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_u8(obj_type as u8);
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_i8(pitch);
    out.put_i8(yaw);
    VarInt(thrower_eid).encode(&mut out).unwrap();
    if thrower_eid > 0 && body.remaining() >= 6 {
        out.put_i16(body.get_i16());
        out.put_i16(body.get_i16());
        out.put_i16(body.get_i16());
    }
    ConversionResult::Converted(vec![build_payload(V112_S2C_SPAWN_OBJECT, &out)])
}

/// 1.6.4 SpawnMob (Packet24, 0x18):
///   `[i32 eid][i8 type][i32 x][i32 y][i32 z][i8 pitch][i8 head_pitch][i8 yaw]`
///   `[i16 vx][i16 vy][i16 vz][metadata]`.
/// 1.12.2 SpawnMob (0x03):
///   `[VarInt eid][u8 type][f64 x][f64 y][f64 z][i8 pitch][i8 head_pitch][i8 yaw]`
///   `[i16 vx][i16 vy][i16 vz][metadata]`.
fn s2c_spawn_mob(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 1 + 4 + 4 + 4 + 1 + 1 + 1 + 2 + 2 + 2 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mob_type = body.get_u8();
    let x = body.get_i32() as f64 / 32.0;
    let y = body.get_i32() as f64 / 32.0;
    let z = body.get_i32() as f64 / 32.0;
    let yaw = body.get_i8();
    let pitch = body.get_i8();
    let head_pitch = body.get_i8();
    let vx = body.get_i16();
    let vy = body.get_i16();
    let vz = body.get_i16();
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_u8(mob_type);
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_i8(yaw);
    out.put_i8(pitch);
    out.put_i8(head_pitch);
    out.put_i16(vx);
    out.put_i16(vy);
    out.put_i16(vz);
    out.put_u8(0x7F); // metadata terminator
    ConversionResult::Converted(vec![build_payload(V112_S2C_SPAWN_MOB, &out)])
}

/// 1.6.4 SpawnPainting (Packet25, 0x19):
///   `[i32 eid][UCS-2 title][i32 x][i32 y][i32 z][i32 direction]`.
/// 1.12.2 SpawnPainting (0x04):
///   `[VarInt eid][UUID][i64 packed_position][i8 direction][String title]`.
fn s2c_spawn_painting(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 2 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let title_len = body.get_u16() as usize;
    if body.remaining() < title_len * 2 + 4 + 4 + 4 + 4 {
        return ConversionResult::Passthrough;
    }
    let mut title_u16 = Vec::with_capacity(title_len);
    for _ in 0..title_len {
        title_u16.push(body.get_u16());
    }
    let title = String::from_utf16_lossy(&title_u16);
    let x = body.get_i32();
    let y = body.get_i32();
    let z = body.get_i32();
    let direction = body.get_i32();
    let pos = kojacoord_protocol::types::Position { x, y, z };
    let packed = kojacoord_protocol::types::encode_legacy_position(pos);
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    let uid = uuid::Uuid::new_v4();
    let (hi, lo) = uid.as_u64_pair();
    out.put_i64(hi as i64);
    out.put_i64(lo as i64);
    out.put_i64(packed);
    out.put_i8(direction as i8);
    VarInt(title.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(title.as_bytes());
    ConversionResult::Converted(vec![build_payload(V112_S2C_SPAWN_PAINTING, &out)])
}

/// 1.6.4 SpawnExperienceOrb (Packet26, 0x1A):
///   `[i32 eid][i32 x][i32 y][i32 z][i16 count]`.
/// 1.12.2 SpawnExperienceOrb (0x01):
///   `[VarInt eid][f64 x][f64 y][f64 z][u16 count]`.
fn s2c_spawn_exp_orb(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 4 + 4 + 4 + 2 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let x = body.get_i32() as f64 / 32.0;
    let y = body.get_i32() as f64 / 32.0;
    let z = body.get_i32() as f64 / 32.0;
    let count = body.get_i16();
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    out.put_i16(count);
    ConversionResult::Converted(vec![build_payload(V112_S2C_SPAWN_EXP_ORB, &out)])
}

/// 1.6.4 EntityVelocity (Packet28, 0x1C):
///   `[i32 eid][i16 vx][i16 vy][i16 vz]`.
/// 1.12.2 EntityVelocity (0x3E):
///   `[VarInt eid][i16 vx][i16 vy][i16 vz]`. Same shape, just VarInt eid.
fn s2c_entity_velocity(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 10 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let vx = body.get_i16();
    let vy = body.get_i16();
    let vz = body.get_i16();
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_i16(vx);
    out.put_i16(vy);
    out.put_i16(vz);
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_VELOCITY, &out)])
}

/// 1.6.4 EntityLook (Packet32, 0x20): `[i32 eid][i8 yaw][i8 pitch]`.
/// 1.12.2 EntityLook (0x28): `[VarInt eid][i8 yaw][i8 pitch][bool on_ground]`.
fn s2c_entity_look(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 6 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let yaw = body.get_i8();
    let pitch = body.get_i8();
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_i8(yaw);
    out.put_i8(pitch);
    out.put_u8(0); // on_ground
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_LOOK, &out)])
}

/// 1.6.4 EntityLookAndRelativeMove (Packet33, 0x21):
///   `[i32 eid][i8 dx][i8 dy][i8 dz][i8 yaw][i8 pitch]`.
/// 1.12.2 EntityLookAndRelativeMove (0x27):
///   `[VarInt eid][i16 dx][i16 dy][i16 dz][i8 yaw][i8 pitch][bool on_ground]`.
/// Deltas in 1.6.4 are fp(32), in 1.12.2 fp(4096). Convert by ×128.
fn s2c_entity_look_rel_move(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 9 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let dx = body.get_i8() as i16 * 128;
    let dy = body.get_i8() as i16 * 128;
    let dz = body.get_i8() as i16 * 128;
    let yaw = body.get_i8();
    let pitch = body.get_i8();
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_i16(dx);
    out.put_i16(dy);
    out.put_i16(dz);
    out.put_i8(yaw);
    out.put_i8(pitch);
    out.put_u8(0); // on_ground
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_LOOK_REL_MOVE, &out)])
}

/// 1.6.4 EntityStatus (Packet38, 0x26): `[i32 eid][i8 status]`.
/// 1.12.2 EntityStatus (0x1B): `[i32 eid][i8 status]`. Same shape.
fn s2c_entity_status(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 5 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let status = body.get_i8();
    let mut out = BytesMut::new();
    out.put_i32(eid);
    out.put_i8(status);
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_STATUS, &out)])
}

/// 1.6.4 AttachEntity (Packet39, 0x27):
///   `[i32 riding_eid][i32 vehicle_eid][u8 attach_state]`.
/// 1.12.2 AttachEntity (0x1C): same shape.
fn s2c_attach_entity(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 9 {
        return ConversionResult::Passthrough;
    }
    let riding = body.get_i32();
    let vehicle = body.get_i32();
    let state = body.get_u8();
    let mut out = BytesMut::new();
    out.put_i32(riding);
    out.put_i32(vehicle);
    out.put_u8(state);
    ConversionResult::Converted(vec![build_payload(V112_S2C_ATTACH_ENTITY, &out)])
}

/// 1.6.4 EntityMetadata (Packet40, 0x28): `[i32 eid][metadata]`.
/// 1.12.2 EntityMetadata (0x39): `[VarInt eid][metadata]`.
/// Metadata wire format differs structurally between versions — stub the
/// metadata blob with just the terminator byte (0x7F) to avoid sending
/// garbage. The client will receive an empty metadata update.
fn s2c_entity_metadata(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_u8(0x7F); // metadata terminator
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_METADATA, &out)])
}

/// 1.6.4 EntityEffect (Packet41, 0x29):
///   `[i32 eid][i8 effect_id][i8 amplifier][i16 duration]`.
/// 1.12.2 EntityEffect (0x3B):
///   `[VarInt eid][i8 effect_id][i8 amplifier][i16 duration][i8 hide_particles]`.
fn s2c_entity_effect(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let effect_id = body.get_i8();
    let amplifier = body.get_i8();
    let duration = body.get_i16();
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_i8(effect_id);
    out.put_i8(amplifier);
    out.put_i16(duration);
    out.put_u8(0); // hide_particles = false
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_EFFECT, &out)])
}

/// 1.6.4 RemoveEntityEffect (Packet42, 0x2A): `[i32 eid][i8 effect_id]`.
/// 1.12.2 RemoveEntityEffect (0x3C): `[VarInt eid][i8 effect_id]`.
fn s2c_remove_entity_effect(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 5 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let effect_id = body.get_i8();
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_i8(effect_id);
    ConversionResult::Converted(vec![build_payload(V112_S2C_REMOVE_ENTITY_EFFECT, &out)])
}

/// 1.6.4 EntityProperties (Packet44, 0x2C):
///   `[i32 eid][i32 count]{String key, f64 value, i16 modifier_count,
///    {i64 uuid_hi, i64 uuid_lo, f64 amount, i8 operation}×N}×N`.
/// 1.12.2 EntityProperties (0x3D): same structural shape but with VarInt eid.
/// Wire format is otherwise identical — pass through the body after
/// re-encoding the eid.
fn s2c_entity_properties(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V112_S2C_ENTITY_PROPERTIES, &out)])
}

/// 1.6.4 MultiBlockChange (Packet52, 0x34):
///   `[i32 chunk_x][i32 chunk_z][i16 count][i32 data_size]{records...}`.
/// 1.12.2 MultiBlockChange (0x0A):
///   `[i32 chunk_x][i32 chunk_z]{VarInt count, records...}`.
/// Wire restructure is non-trivial; drop rather than risk a bad read.
fn s2c_multi_block_change(_body: Bytes) -> ConversionResult {
    ConversionResult::Drop
}

/// 1.6.4 BlockAction (Packet54, 0x36):
///   `[i32 x][i16 y][i32 z][i8 byte1][i8 byte2][i16 block_id]`.
/// 1.12.2 BlockAction (0x0C):
///   `[i64 packed_position][u8 byte1][u8 byte2][VarInt block_type]`.
fn s2c_block_action(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 2 + 4 + 1 + 1 + 2 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32();
    let y = body.get_i16() as i32;
    let z = body.get_i32();
    let byte1 = body.get_i8();
    let byte2 = body.get_i8();
    let block_id = body.get_i16();
    let pos = kojacoord_protocol::types::Position { x, y, z };
    let packed = kojacoord_protocol::types::encode_legacy_position(pos);
    let mut out = BytesMut::new();
    out.put_i64(packed);
    out.put_i8(byte1);
    out.put_i8(byte2);
    VarInt(block_id as i32).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_S2C_BLOCK_ACTION, &out)])
}

/// 1.6.4 BlockBreakAnimation (Packet55, 0x37):
///   `[i32 breaker_eid][i32 x][i8 y][i32 z][i8 stage]`.
/// 1.12.2 BlockBreakAnimation (0x0D):
///   `[VarInt breaker_eid][i64 packed_position][i8 stage]`.
fn s2c_block_break_animation(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 4 + 1 + 4 + 1 {
        return ConversionResult::Passthrough;
    }
    let breaker_eid = body.get_i32();
    let x = body.get_i32();
    let y = body.get_i8() as i32;
    let z = body.get_i32();
    let stage = body.get_i8();
    let pos = kojacoord_protocol::types::Position { x, y, z };
    let packed = kojacoord_protocol::types::encode_legacy_position(pos);
    let mut out = BytesMut::new();
    VarInt(breaker_eid).encode(&mut out).unwrap();
    out.put_i64(packed);
    out.put_i8(stage);
    ConversionResult::Converted(vec![build_payload(V112_S2C_BLOCK_BREAK_ANIMATION, &out)])
}

/// 1.6.4 Explosion (Packet60, 0x3C):
///   `[f64 x][f64 y][f64 z][f32 radius][i32 count]{records}[f32 vx][f32 vy][f32 vz]`.
/// 1.12.2 Explosion (0x1C):
///   `[f32 x][f32 y][f32 z][f32 radius][i32 count]{records}[f32 vx][f32 vy][f32 vz]`.
/// 1.6.4 uses f64 for position, 1.12.2 uses f32. Convert.
fn s2c_explosion(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 + 8 + 8 + 4 + 4 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_f64() as f32;
    let y = body.get_f64() as f32;
    let z = body.get_f64() as f32;
    let radius = body.get_f32();
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let count = body.get_i32();
    if count < 0 || (count as usize) * 3 > body.remaining() {
        return ConversionResult::Passthrough;
    }
    let mut records = Vec::with_capacity(count as usize * 3);
    for _ in 0..count {
        records.push(body.get_i8());
    }
    if body.remaining() < 4 + 4 + 4 {
        return ConversionResult::Passthrough;
    }
    let vx = body.get_f32();
    let vy = body.get_f32();
    let vz = body.get_f32();
    let mut out = BytesMut::new();
    out.put_f32(x);
    out.put_f32(y);
    out.put_f32(z);
    out.put_f32(radius);
    out.put_i32(count);
    for r in &records {
        out.put_i8(*r);
    }
    out.put_f32(vx);
    out.put_f32(vy);
    out.put_f32(vz);
    ConversionResult::Converted(vec![build_payload(V112_S2C_EXPLOSION, &out)])
}

/// 1.6.4 Effect (Packet61, 0x3D):
///   `[i32 effect_id][i32 x][u8 y][i32 z][i32 data][bool disable_volume]`.
/// 1.12.2 Effect (0x22): `[i32 effect_id][i64 packed position][i32 data][bool disable_volume]`.
fn s2c_effect(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 4 + 1 + 4 + 4 + 1 {
        return ConversionResult::Passthrough;
    }
    let effect_id = body.get_i32();
    let x = body.get_i32();
    let y = body.get_u8() as i32;
    let z = body.get_i32();
    let data = body.get_i32();
    let disable_volume = body.get_u8() != 0;
    let pos = kojacoord_protocol::types::Position { x, y, z };
    let packed = kojacoord_protocol::types::encode_legacy_position(pos);
    let mut out = BytesMut::new();
    out.put_i32(effect_id);
    out.put_i64(packed);
    out.put_i32(data);
    out.put_u8(if disable_volume { 1 } else { 0 });
    ConversionResult::Converted(vec![build_payload(V112_S2C_EFFECT, &out)])
}

/// 1.6.4 NamedSoundEffect (Packet62, 0x3E):
///   `[UCS-2 name][i32 x][i32 y][i32 z][f32 volume][i8 pitch]`.
/// 1.12.2 NamedSoundEffect (0x49):
///   `[String name][VarInt category][i32 x][i32 y][i32 z][f32 volume][f32 pitch]`.
fn s2c_named_sound(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let name_len = body.get_u16() as usize;
    if body.remaining() < name_len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut chars = Vec::with_capacity(name_len);
    for _ in 0..name_len {
        chars.push(body.get_u16());
    }
    let name = String::from_utf16_lossy(&chars);
    if body.remaining() < 4 + 4 + 4 + 4 + 1 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32();
    let y = body.get_i32();
    let z = body.get_i32();
    let volume = body.get_f32();
    let pitch = body.get_i8();
    let mut out = BytesMut::new();
    VarInt(name.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(name.as_bytes());
    VarInt(0).encode(&mut out).unwrap(); // category = master
    out.put_i32(x);
    out.put_i32(y);
    out.put_i32(z);
    out.put_f32(volume);
    out.put_f32(pitch as f32 / 63.0); // 1.6 stores pitch as i8 steps of 1/64
    ConversionResult::Converted(vec![build_payload(V112_S2C_NAMED_SOUND, &out)])
}

/// 1.6.4 Particle (Packet63, 0x3F):
///   `[UCS-2 name][f32 x][f32 y][f32 z][f32 ox][f32 oy][f32 oz][f32 speed][i32 count]`.
/// No simple 1.12.2 particle equivalent with same name-based dispatch — drop.
fn s2c_particle(_body: Bytes) -> ConversionResult {
    ConversionResult::Drop
}

/// 1.6.4 ChangeGameState (Packet70, 0x46): `[u8 reason][f32 value]`.
/// 1.12.2 ChangeGameState (0x1E): `[u8 reason][f32 value]`. Same shape.
fn s2c_game_state(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 + 4 {
        return ConversionResult::Passthrough;
    }
    let reason = body.get_u8();
    let value = body.get_f32();
    let mut out = BytesMut::new();
    out.put_u8(reason);
    out.put_f32(value);
    ConversionResult::Converted(vec![build_payload(V112_S2C_GAME_STATE, &out)])
}

/// 1.6.4 SpawnGlobalEntity / Weather (Packet71, 0x47):
///   `[i32 eid][i8 type][i32 x][i32 y][i32 z]`.
/// 1.12.2 SpawnGlobalEntity (0x02):
///   `[VarInt eid][u8 type][f64 x][f64 y][f64 z]`.
fn s2c_spawn_global_entity(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 1 + 4 + 4 + 4 {
        return ConversionResult::Passthrough;
    }
    let eid = body.get_i32();
    let etype = body.get_u8();
    let x = body.get_i32() as f64 / 32.0;
    let y = body.get_i32() as f64 / 32.0;
    let z = body.get_i32() as f64 / 32.0;
    let mut out = BytesMut::new();
    VarInt(eid).encode(&mut out).unwrap();
    out.put_u8(etype);
    out.put_f64(x);
    out.put_f64(y);
    out.put_f64(z);
    ConversionResult::Converted(vec![build_payload(V112_S2C_SPAWN_GLOBAL_ENTITY, &out)])
}

/// 1.6.4 OpenWindow (Packet100, 0x64):
///   `[u8 window_id][u8 inv_type][UCS-2 title][u8 slot_count][bool use_provided_title]`
///   + `[i32 entity_id]` if inv_type==11.
/// 1.12.2 OpenWindow (0x13):
///   `[u8 window_id][String type][String title][u8 slot_count]`
///   + `[i32 entity_id]` if type=="EntityHorse".
fn s2c_open_window(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 + 1 + 2 {
        return ConversionResult::Passthrough;
    }
    let window_id = body.get_u8();
    let inv_type = body.get_u8();
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let title_len = body.get_u16() as usize;
    if body.remaining() < title_len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut title_chars = Vec::with_capacity(title_len);
    for _ in 0..title_len {
        title_chars.push(body.get_u16());
    }
    let title = String::from_utf16_lossy(&title_chars);
    if body.remaining() < 1 + 1 {
        return ConversionResult::Passthrough;
    }
    let slot_count = body.get_u8();
    let _use_provided = body.get_u8();
    let mut entity_id: i32 = 0;
    if inv_type == 11 && body.remaining() >= 4 {
        entity_id = body.get_i32();
    }
    let type_str = match inv_type {
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
        10 => "minecraft:shulker_box",
        11 => "EntityHorse",
        _ => "minecraft:chest",
    };
    let mut out = BytesMut::new();
    out.put_u8(window_id);
    VarInt(type_str.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(type_str.as_bytes());
    VarInt(title.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(title.as_bytes());
    out.put_u8(slot_count);
    if inv_type == 11 {
        VarInt(entity_id).encode(&mut out).unwrap();
    }
    ConversionResult::Converted(vec![build_payload(V112_S2C_OPEN_WINDOW, &out)])
}

/// 1.6.4 CloseWindow S2C (Packet101, 0x65): `[u8 window_id]`.
/// 1.12.2 CloseWindow S2C (0x12): `[u8 window_id]`. Same shape.
fn s2c_close_window_s2c(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let wid = body.get_u8();
    let mut out = BytesMut::new();
    out.put_u8(wid);
    ConversionResult::Converted(vec![build_payload(V112_S2C_CLOSE_WINDOW, &out)])
}

/// 1.6.4 UpdateWindowProperty (Packet105, 0x69):
///   `[u8 window_id][i16 property][i16 value]`.
/// 1.12.2 WindowProperty (0x11): same shape.
fn s2c_update_window_property(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 + 2 + 2 {
        return ConversionResult::Passthrough;
    }
    let wid = body.get_u8();
    let property = body.get_i16();
    let value = body.get_i16();
    let mut out = BytesMut::new();
    out.put_u8(wid);
    out.put_i16(property);
    out.put_i16(value);
    ConversionResult::Converted(vec![build_payload(V112_S2C_UPDATE_WINDOW_PROPERTY, &out)])
}

/// 1.6.4 ConfirmTransaction S2C (Packet106, 0x6A):
///   `[u8 window_id][i16 action][bool accepted]`.
/// 1.12.2 ConfirmTransaction S2C (0x10): same shape.
fn s2c_confirm_transaction_s2c(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 {
        return ConversionResult::Passthrough;
    }
    let wid = body.get_u8();
    let action = body.get_i16();
    let accepted = body.get_u8();
    let mut out = BytesMut::new();
    out.put_u8(wid);
    out.put_i16(action);
    out.put_u8(accepted);
    ConversionResult::Converted(vec![build_payload(V112_S2C_CONFIRM_TRANSACTION, &out)])
}

/// 1.6.4 UpdateTileEntity (Packet132, 0x84):
///   `[i32 x][i16 y][i32 z][i8 action][NBT data]`.
/// 1.12.2 UpdateTileEntity: `[i64 packed_position][u8 action][NBT data]`.
fn s2c_update_tile_entity(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 2 + 4 + 1 {
        return ConversionResult::Passthrough;
    }
    let x = body.get_i32();
    let y = body.get_i16() as i32;
    let z = body.get_i32();
    let action = body.get_u8();
    let pos = kojacoord_protocol::types::Position { x, y, z };
    let packed = kojacoord_protocol::types::encode_legacy_position(pos);
    let mut out = BytesMut::new();
    out.put_i64(packed);
    out.put_u8(action);
    out.extend_from_slice(&body);
    ConversionResult::Converted(vec![build_payload(V112_S2C_TILE_ENTITY_DATA, &out)])
}

/// 1.6.4 ItemData (Packet131, 0x83): drop — no 1.12.2 equivalent.
fn s2c_item_data(_body: Bytes) -> ConversionResult {
    ConversionResult::Drop
}

/// 1.6.4 Statistic (Packet200, 0xC8): `[i32 stat_id][i8 amount]`.
/// 1.12.2 Statistic (0x07): `[VarInt count][{VarInt stat_id, VarInt value}×N]`.
fn s2c_statistic(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 5 {
        return ConversionResult::Passthrough;
    }
    let stat_id = body.get_i32();
    let amount = body.get_i8();
    let mut out = BytesMut::new();
    VarInt(1).encode(&mut out).unwrap(); // count = 1
    VarInt(stat_id).encode(&mut out).unwrap();
    VarInt(amount as i32).encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V112_S2C_STATISTIC, &out)])
}

/// 1.6.4 PlayerListItem (Packet201, 0xC9):
///   `[UCS-2 name][bool online][i16 ping]`.
/// 1.12.2 PlayerListItem (0x2E): entirely different structure (UUID-based).
/// Synthesise a minimal add-entry using a fake UUID derived from the name.
fn s2c_player_list_item(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let name_len = body.get_u16() as usize;
    if body.remaining() < name_len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut name_chars = Vec::with_capacity(name_len);
    for _ in 0..name_len {
        name_chars.push(body.get_u16());
    }
    let name = String::from_utf16_lossy(&name_chars);
    if body.remaining() < 1 + 2 {
        return ConversionResult::Passthrough;
    }
    let _online = body.get_u8() != 0;
    let _ping = body.get_i16();
    let mut out = BytesMut::new();
    VarInt(0).encode(&mut out).unwrap(); // action = ADD_PLAYER
    VarInt(1).encode(&mut out).unwrap(); // entry count = 1
    let fake_uuid = uuid::Uuid::new_v4();
    let (hi, lo) = fake_uuid.as_u64_pair();
    out.put_i64(hi as i64);
    out.put_i64(lo as i64);
    VarInt(name.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(name.as_bytes());
    VarInt(0).encode(&mut out).unwrap(); // gamemode = survival
    VarInt(0).encode(&mut out).unwrap(); // ping = 0
    out.put_u8(0); // has display name = false
    ConversionResult::Converted(vec![build_payload(V112_S2C_PLAYER_LIST_ITEM, &out)])
}

/// 1.6.4 ScoreboardObjective (Packet206, 0xCE):
///   `[UCS-2 name][UCS-2 value][u8 mode]`.
/// 1.12.2 ScoreboardObjective (0x41):
///   `[String name][String value][VarInt mode]`.
/// Mode 1 = remove, mode 0/2 = create/update. In mode 1 the value is absent.
fn s2c_scoreboard_objective(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let name_len = body.get_u16() as usize;
    if body.remaining() < name_len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut chars = Vec::with_capacity(name_len);
    for _ in 0..name_len {
        chars.push(body.get_u16());
    }
    let name = String::from_utf16_lossy(&chars);
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let value_len = body.get_u16() as usize;
    if body.remaining() < value_len * 2 + 1 {
        return ConversionResult::Passthrough;
    }
    let mut value_chars = Vec::with_capacity(value_len);
    for _ in 0..value_len {
        value_chars.push(body.get_u16());
    }
    let value = String::from_utf16_lossy(&value_chars);
    let mode = body.get_u8();
    let mut out = BytesMut::new();
    VarInt(name.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(name.as_bytes());
    if mode == 1 {
        VarInt(1).encode(&mut out).unwrap();
    } else {
        VarInt(if mode == 0 { 0 } else { 2 }).encode(&mut out).unwrap();
        VarInt(value.len() as i32).encode(&mut out).unwrap();
        out.extend_from_slice(value.as_bytes());
        VarInt(0).encode(&mut out).unwrap(); // type = "integer"
    }
    ConversionResult::Converted(vec![build_payload(V112_S2C_SCOREBOARD_OBJECTIVE, &out)])
}

/// 1.6.4 UpdateScore (Packet207, 0xCF):
///   `[UCS-2 item_name][u8 mode][UCS-2 objective_name][i32 value]`.
/// 1.12.2 UpdateScore (0x44):
///   `[String item_name][VarInt mode][String objective_name][VarInt value]`.
/// Mode 1 = remove — no objective/value after.
fn s2c_update_score(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let item_len = body.get_u16() as usize;
    if body.remaining() < item_len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut chars = Vec::with_capacity(item_len);
    for _ in 0..item_len {
        chars.push(body.get_u16());
    }
    let item = String::from_utf16_lossy(&chars);
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let mode = body.get_u8();
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let obj_len = body.get_u16() as usize;
    if body.remaining() < obj_len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut obj_chars = Vec::with_capacity(obj_len);
    for _ in 0..obj_len {
        obj_chars.push(body.get_u16());
    }
    let objective = String::from_utf16_lossy(&obj_chars);
    let mut out = BytesMut::new();
    VarInt(item.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(item.as_bytes());
    if mode == 1 {
        VarInt(1).encode(&mut out).unwrap();
        VarInt(objective.len() as i32).encode(&mut out).unwrap();
        out.extend_from_slice(objective.as_bytes());
    } else {
        VarInt(0).encode(&mut out).unwrap();
        VarInt(objective.len() as i32).encode(&mut out).unwrap();
        out.extend_from_slice(objective.as_bytes());
        if body.remaining() >= 4 {
            let value = body.get_i32();
            VarInt(value).encode(&mut out).unwrap();
        }
    }
    ConversionResult::Converted(vec![build_payload(V112_S2C_UPDATE_SCORE, &out)])
}

/// 1.6.4 DisplayScoreboard (Packet208, 0xD0): `[u8 position][UCS-2 name]`.
/// 1.12.2 DisplayScoreboard (0x3A): `[u8 position][String name]`.
fn s2c_display_scoreboard(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 1 + 2 {
        return ConversionResult::Passthrough;
    }
    let position = body.get_u8();
    let name_len = body.get_u16() as usize;
    if body.remaining() < name_len * 2 {
        return ConversionResult::Passthrough;
    }
    let mut chars = Vec::with_capacity(name_len);
    for _ in 0..name_len {
        chars.push(body.get_u16());
    }
    let name = String::from_utf16_lossy(&chars);
    let mut out = BytesMut::new();
    out.put_u8(position);
    VarInt(name.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(name.as_bytes());
    ConversionResult::Converted(vec![build_payload(V112_S2C_DISPLAY_SCOREBOARD, &out)])
}

/// 1.6.4 Teams (Packet209, 0xD1): complex variable-length structure.
/// Drop — the 1.12.2 wire format differs significantly.
fn s2c_teams(_body: Bytes) -> ConversionResult {
    ConversionResult::Drop
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
const V164_C2S_STEER_VEHICLE: u8 = 0x1B; // Packet27PlayerInput
const V164_C2S_CREATIVE_INVENTORY_ACTION: u8 = 0x6B; // Packet107CreativeSetSlot
const V164_C2S_ENCHANT_ITEM: u8 = 0x6C; // Packet108EnchantItem

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
const V112_C2S_STEER_VEHICLE_OUT: u8 = 0x16;
const V112_C2S_CREATIVE_INVENTORY_ACTION_OUT: u8 = 0x1B;
const V112_C2S_ENCHANT_ITEM_OUT: u8 = 0x06;

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
        V164_C2S_STEER_VEHICLE => c2s_steer_vehicle(body),
        V164_C2S_CREATIVE_INVENTORY_ACTION => c2s_creative_inventory_action(body),
        V164_C2S_ENCHANT_ITEM => c2s_enchant_item(body),
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

/// 1.6.4 SteerVehicle (Packet27, 0x1B):
///   `[f32 sideways][f32 forward][bool jump][bool unmount]`.
/// 1.12.2 SteerVehicle (0x16):
///   `[f32 sideways][f32 forward][u8 flags]` (flags: bit 0=jump, bit 1=unmount).
fn c2s_steer_vehicle(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 4 + 4 + 1 + 1 {
        return ConversionResult::Passthrough;
    }
    let sideways = body.get_f32();
    let forward = body.get_f32();
    let jump = body.get_u8() != 0;
    let unmount = body.get_u8() != 0;
    let mut flags: u8 = 0;
    if jump {
        flags |= 0x01;
    }
    if unmount {
        flags |= 0x02;
    }
    let mut out = BytesMut::new();
    out.put_f32(sideways);
    out.put_f32(forward);
    out.put_u8(flags);
    ConversionResult::Converted(vec![build_payload(V112_C2S_STEER_VEHICLE_OUT, &out)])
}

/// 1.6.4 CreativeInventoryAction (Packet107, 0x6B):
///   `[i16 slot][Slot item]`.
/// 1.12.2 CreativeInventoryAction (0x18):
///   `[i16 slot][Slot item]`. Same shape, just remap id.
/// We emit an empty slot to avoid wire-format mismatch on the Slot payload.
fn c2s_creative_inventory_action(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let slot = body.get_i16();
    let mut out = BytesMut::new();
    out.put_i16(slot);
    out.put_u8(0); // empty Slot
    ConversionResult::Converted(vec![build_payload(V112_C2S_CREATIVE_INVENTORY_ACTION_OUT, &out)])
}

/// 1.6.4 EnchantItem (Packet108, 0x6C):
///   `[u8 window_id][u8 enchantment]`.
/// 1.12.2 EnchantItem (0x1B): same shape.
fn c2s_enchant_item(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 2 {
        return ConversionResult::Passthrough;
    }
    let wid = body.get_u8();
    let enchantment = body.get_u8();
    let mut out = BytesMut::new();
    out.put_u8(wid);
    out.put_u8(enchantment);
    ConversionResult::Converted(vec![build_payload(V112_C2S_ENCHANT_ITEM_OUT, &out)])
}
