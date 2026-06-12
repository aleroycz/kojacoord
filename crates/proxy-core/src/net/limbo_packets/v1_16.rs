//! Limbo packets for the v1_16_x canonical bucket (1.13 – 1.16.5).

use bytes::{BufMut, BytesMut};
use kojacoord_protocol::codec::Encode;
use kojacoord_protocol::types::VarInt;
use kojacoord_protocol::versions::v1_16_x::play as p;
use uuid::Uuid;

use super::{encode, EncodedPacket, LimboPackets, PlayerPos, SoundParams};

pub struct V1_16;

impl LimboPackets for V1_16 {
    fn join_game(&self, proto: u32, world_name: &str) -> Option<EncodedPacket> {
        // Hard guard: v1_13/v1_14/v1_15 (protos 393–578) ALIAS to V1_16
        // (see limbo_packets/v1_13.rs / v1_14.rs / v1_15.rs). Their
        // JoinGame wire shape is the legacy `i32 dimension + String
        // levelType` form (no `world_names`, no dimension_codec NBT).
        // Per BungeeCord `Login.java::read`, the codec field exists only
        // from proto 735 (MINECRAFT_1_16) onward.
        //
        // Returning None here for those protos matches the same
        // skip-pattern v1_19::join_game uses for protos < 759 — the
        // limbo handler tolerates a missing JoinGame and the connection
        // sits in pre-play state until the backend comes back.
        // Without this guard, 1.13/1.14/1.15 limbo emitted a JoinGame
        // with dimension_codec NBT bytes the client misparsed as the
        // i32 dimension field, immediately disconnecting.
        // Pre-1.16 JoinGame in the V1_16 limbo bucket (protos 393-578
        // → 1.13 / 1.14 / 1.15) uses the legacy shape — no codec NBT,
        // i32 dimension, String level_type, plus a few wire-shape
        // tweaks at each minor:
        //   proto 393-404 (1.13)    : entity_id, gamemode, dimension,
        //                             difficulty, max_players, level_type,
        //                             reduced_debug_info
        //   proto 477-498 (1.14)    : + VarInt view_distance (between
        //                             level_type and reduced_debug_info)
        //   proto 573-578 (1.15)    : drops `difficulty`, adds
        //                             `hashed_seed: i64` + the 1.16-style
        //                             `enable_respawn_screen` bool
        // Hand-encode here per minecraft.wiki Java_Edition_protocol
        // §Join_Game / BungeeCord `Login.java` per-version branches.
        if proto < 735 {
            return build_join_game_1_13_through_1_15(proto, world_name);
        }
        // 1.16.0 / 1.16.1 (proto 735/736) JoinGame doesn't have the
        // `is_hardcore` boolean field — Mojang added it at 1.16.2
        // (proto 751). Per BungeeCord `Login.java::write` the gate is
        // `if (protocolVersion >= MINECRAFT_1_16_2) writeBoolean(isHardcore)`.
        //
        // The v1_16 typed encoder writes it unconditionally, so for
        // proto 735/736 we hand-encode the legacy shape. Without this
        // the 1.16.0 client reads `gamemode` from our `is_hardcore`
        // slot, `previous_gamemode` from our `gamemode` slot, and
        // `previous_gamemode=-1=0xFF` as a VarInt continuation byte
        // for `world_count` — making it huge, after which the parser
        // reads codec NBT bytes as Identifier strings and emits
        // `"Non [a-z0-9/_-] character in path of location: minecraft:<garbage>"`.
        if proto == 735 || proto == 736 {
            return build_join_game_1_16_0_or_1_16_1(proto, world_name);
        }
        // 1.16+ JoinGame requires a Dimension Codec NBT — without it the
        // client reads the next field's bytes as the codec and falls off
        // the wire format. We synthesise a minimal codec (one overworld
        // dimension, default biome registry) via the proxy-core helper.
        let dimension_codec = crate::protocol::build_dimension_codec_for_proto(proto).ok()?;
        // `dimension` field type per BungeeCord:
        //   proto 735, 736 (1.16 / 1.16.1)        → Identifier String
        //   proto 751-758 (1.16.2 — 1.18.2)       → NBT
        //   proto 759+ (1.19+)                     → Identifier String
        let dimension = if (751..=758).contains(&proto) {
            p::DimensionRef::Nbt(
                crate::protocol::dimension_type_nbt_for_proto("minecraft:overworld", proto).ok()?,
            )
        } else {
            p::DimensionRef::Identifier("minecraft:overworld".to_owned())
        };
        encode(
            proto,
            p::ClientboundJoinGame {
                entity_id: 0,
                is_hardcore: false,
                game_mode: 3,
                previous_game_mode: -1,
                world_names: vec![world_name.to_owned()],
                dimension_codec,
                dimension,
                world_name: world_name.to_owned(),
                hashed_seed: 0,
                max_players: VarInt(20),
                view_distance: VarInt(8),
                reduced_debug_info: false,
                enable_respawn_screen: true,
                is_debug: false,
                is_flat: true,
            },
        )
    }

    fn respawn(&self, proto: u32, world_name: &str) -> Option<EncodedPacket> {
        // Pre-1.16 Respawn — 1.13 / 1.14 / 1.15 use the legacy form:
        //   proto 393-498: i32 dimension, u8 difficulty, u8 gamemode,
        //                  String level_type
        //   proto 573-578 (1.15): drops difficulty, adds i64 hashed_seed
        //                         (after gamemode), keeps level_type
        // Per minecraft.wiki §Respawn / BungeeCord `Respawn.java`.
        if proto < 735 {
            return build_respawn_1_13_through_1_15(proto);
        }
        encode(
            proto,
            p::ClientboundRespawn {
                dimension: "minecraft:overworld".to_owned(),
                world_name: world_name.to_owned(),
                hashed_seed: 0,
                game_mode: 0,
                previous_game_mode: -1,
                is_debug: false,
                is_flat: true,
                copy_metadata: false,
            },
        )
    }

    fn player_abilities(&self, proto: u32) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundPlayerAbilities {
                flags: 0x06,
                flying_speed: 0.0,
                walking_speed: 0.0,
            },
        )
    }

    fn held_item_change(&self, proto: u32) -> Option<EncodedPacket> {
        encode(proto, p::ClientboundHeldItemChange { slot: 0 })
    }

    fn player_position(
        &self,
        proto: u32,
        pos: PlayerPos,
        teleport_id: i32,
    ) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundPlayerPosition {
                x: pos.x,
                y: pos.y,
                z: pos.z,
                yaw: pos.yaw,
                pitch: pos.pitch,
                flags: 0,
                teleport_id: VarInt(teleport_id),
            },
        )
    }

    fn chat(&self, proto: u32, json_message: &str) -> Option<EncodedPacket> {
        // ChatMessage wire shape:
        //   * proto 393 - 578 (1.13 / 1.14 / 1.15): `[String json][i8 position]`
        //   * proto 735+      (1.16+)             : `[String json][i8 position][UUID sender]`
        //
        // The 16-byte `sender` UUID was added in 1.16. Sending the
        // 1.16 shape to a 1.13 / 1.14 / 1.15 client makes the client
        // disconnect with `"Packet 0/14 (in) was larger than I
        // expected, found 16 bytes extra whilst reading packet 14"` —
        // verified against minecraft.wiki Java_Edition_protocol/Packets
        // §Chat_Message_(clientbound) per-version table.
        if proto < 735 {
            return build_chat_pre_1_16(proto, json_message);
        }
        encode(
            proto,
            p::ClientboundChatMessage {
                json_message: json_message.to_owned(),
                position: 1,
                sender: Uuid::nil(),
            },
        )
    }

    fn note_sound(&self, proto: u32, pos: SoundParams) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundNamedSoundEffect {
                sound_name: "minecraft:records.cat".to_owned(),
                sound_category: VarInt(2),
                effect_position_x: (pos.x * 8.0) as i32,
                effect_position_y: (pos.y * 8.0) as i32,
                effect_position_z: (pos.z * 8.0) as i32,
                volume: pos.volume,
                pitch: pos.pitch,
            },
        )
    }

    fn bossbar_add(&self, proto: u32, uuid: Uuid, title: &str) -> Option<EncodedPacket> {
        // The v1_16_x module doesn't re-export BossBar after the prune;
        // we reuse the 1.12 typed struct which has the same wire shape
        // on 1.16 (the registry resolves the id correctly per proto).
        encode(
            proto,
            kojacoord_protocol::versions::v1_12_x::play::ClientboundBossBar {
                uuid,
                action: kojacoord_protocol::versions::v1_12_x::play::BossBarAction::Add {
                    title: title.to_owned(),
                    health: 1.0,
                    color: VarInt(1),
                    division: VarInt(0),
                    flags: 0,
                },
            },
        )
    }

    fn bossbar_remove(&self, proto: u32, uuid: Uuid) -> Option<EncodedPacket> {
        encode(
            proto,
            kojacoord_protocol::versions::v1_12_x::play::ClientboundBossBar {
                uuid,
                action: kojacoord_protocol::versions::v1_12_x::play::BossBarAction::Remove,
            },
        )
    }

    fn keepalive(&self, proto: u32, id: i64) -> Option<EncodedPacket> {
        encode(proto, p::ClientboundKeepAlive { keep_alive_id: id })
    }

    fn brand(&self, proto: u32, brand: &str) -> Option<EncodedPacket> {
        let mut data = BytesMut::new();
        VarInt(brand.len() as i32).encode(&mut data).ok()?;
        data.put_slice(brand.as_bytes());
        encode(
            proto,
            kojacoord_protocol::versions::v1_20_x::play::ClientboundPluginMessage {
                channel: "minecraft:brand".to_owned(),
                data: data.to_vec(),
            },
        )
    }
}

/// Hand-encode the pre-1.16 (1.13 / 1.14 / 1.15) ChatMessage.
///
/// Wire shape per minecraft.wiki Java_Edition_protocol/Packets#Chat_Message_(clientbound)
/// for proto 393-578:
///   `[VarInt-prefixed String json][i8 position]`
///
/// The packet id is looked up via the typed
/// `ClientboundChatMessage::packet_id(proto)` fall-through — at 1.13
/// this is `0x0E`, at 1.14 it's `0x0E`, at 1.15 it's `0x0F`. The
/// registry already has these entries; we only need the body shape
/// here.
fn build_chat_pre_1_16(proto: u32, json_message: &str) -> Option<EncodedPacket> {
    use kojacoord_protocol::codec::PacketId;
    let pid = p::ClientboundChatMessage::packet_id(proto);
    if pid == 0xFF {
        return None;
    }
    let mut body = BytesMut::new();
    let bytes = json_message.as_bytes();
    VarInt(bytes.len() as i32).encode(&mut body).ok()?;
    body.put_slice(bytes);
    body.put_i8(1); // position = 1 (system message)
    Some(EncodedPacket { id: pid, body })
}

/// Hand-encode the pre-1.16 (1.13 / 1.14 / 1.15) JoinGame. Packet id
/// is looked up via the typed `ClientboundJoinGame::packet_id(proto)`
/// fall-through (the registry table has the right entry for each
/// proto inside this window — `0x25` on 1.13, `0x25` on 1.14, `0x26`
/// on 1.15).
/// Hand-encode 1.16.0 / 1.16.1 JoinGame (proto 735/736).
///
/// Differs from the v1_16 typed encoder in exactly one place:
/// **no `is_hardcore` Boolean** before `gamemode`. Per minecraft.wiki
/// §JoinGame 1.16 entry + BungeeCord `Login.java::write` gate on
/// `protocolVersion >= MINECRAFT_1_16_2`, the field was added at
/// proto 751.
///
/// Wire shape:
///   `[i32 entity_id] [u8 gamemode] [i8 previous_gamemode]`
///   `[VarInt world_count] [N × String world_name]`
///   `[NBT dimension_codec] [String dimension] [String world_name]`
///   `[i64 hashed_seed] [VarInt max_players] [VarInt view_distance]`
///   `[bool reduced_debug] [bool enable_respawn_screen] [bool is_debug] [bool is_flat]`
fn build_join_game_1_16_0_or_1_16_1(proto: u32, world_name: &str) -> Option<EncodedPacket> {
    use kojacoord_protocol::codec::PacketId;
    let pid = p::ClientboundJoinGame::packet_id(proto);
    if pid == 0xFF {
        return None;
    }
    let dimension_codec = crate::protocol::build_dimension_codec_for_proto(proto).ok()?;

    let mut body = BytesMut::new();
    body.put_i32(0); // entity_id
    body.put_u8(3); // gamemode = spectator (hardcore bit 3 unset)
    body.put_i8(-1); // previous_gamemode

    // world_names: VarInt count + each Identifier
    VarInt(1).encode(&mut body).ok()?;
    let name_bytes = world_name.as_bytes();
    VarInt(name_bytes.len() as i32).encode(&mut body).ok()?;
    body.put_slice(name_bytes);

    body.put_slice(&dimension_codec); // self-framing NBT

    // dimension Identifier (1.16/1.16.1 uses Identifier, not NBT)
    let dim = b"minecraft:overworld";
    VarInt(dim.len() as i32).encode(&mut body).ok()?;
    body.put_slice(dim);

    // world_name Identifier
    VarInt(name_bytes.len() as i32).encode(&mut body).ok()?;
    body.put_slice(name_bytes);

    body.put_i64(0); // hashed_seed
    VarInt(20).encode(&mut body).ok()?; // max_players
    VarInt(8).encode(&mut body).ok()?; // view_distance
    body.put_u8(0); // reduced_debug_info
    body.put_u8(1); // enable_respawn_screen
    body.put_u8(0); // is_debug
    body.put_u8(1); // is_flat

    Some(EncodedPacket { id: pid, body })
}

fn build_join_game_1_13_through_1_15(proto: u32, _world_name: &str) -> Option<EncodedPacket> {
    use kojacoord_protocol::codec::PacketId;
    let pid = p::ClientboundJoinGame::packet_id(proto);
    if pid == 0xFF {
        return None;
    }

    let mut body = BytesMut::new();
    body.put_i32(0); // entity_id
    body.put_u8(0x03); // gamemode = spectator (bit3 = hardcore flag = 0)

    // Per-version field surgery (verified against minecraft.wiki
    // Java_Edition_protocol/Packets §Join_Game per-proto entries +
    // BungeeCord `Login.java` branches):
    //
    //   * 1.13 (proto 393-404): entity_id, gamemode, dimension,
    //                           difficulty, max_players, level_type,
    //                           reduced_debug_info
    //   * 1.14 (proto 477-498): difficulty REMOVED (Mojang moved it
    //                           to the dedicated SetDifficulty packet),
    //                           view_distance ADDED
    //   * 1.15 (proto 573-578): hashed_seed ADDED (after dimension),
    //                           enable_respawn_screen ADDED at end
    //
    // Earlier code gated difficulty on `proto < 573`, which kept it
    // for 1.14 too — the 1.14 client then read max_players (=20, 0x14)
    // at the position where it expected the level_type's VarInt
    // length prefix and crashed with
    // `IndexOutOfBoundsException: index: 12, length: 20`.
    body.put_i32(0); // dimension = overworld
    if proto >= 573 {
        body.put_i64(0); // hashed_seed (1.15+)
    }
    if proto < 477 {
        body.put_u8(0); // difficulty (1.13 only)
    }
    body.put_u8(20); // max_players

    let level_type = "flat".to_string();
    let lt_bytes = level_type.as_bytes();
    VarInt(lt_bytes.len() as i32).encode(&mut body).ok()?;
    body.put_slice(lt_bytes);

    // VarInt view_distance was added in 1.14 (proto 477).
    if proto >= 477 {
        VarInt(8).encode(&mut body).ok()?;
    }
    body.put_u8(0); // reduced_debug_info = false

    // Bool enable_respawn_screen was added in 1.15 (proto 573).
    if proto >= 573 {
        body.put_u8(1);
    }

    Some(EncodedPacket { id: pid, body })
}

/// Hand-encode the pre-1.16 (1.13 / 1.14 / 1.15) Respawn.
fn build_respawn_1_13_through_1_15(proto: u32) -> Option<EncodedPacket> {
    use kojacoord_protocol::codec::PacketId;
    let pid = p::ClientboundRespawn::packet_id(proto);
    if pid == 0xFF {
        return None;
    }

    let mut body = BytesMut::new();
    body.put_i32(0); // dimension = overworld
                     // Per-version Respawn surgery (verified against minecraft.wiki
                     // §Respawn per-proto entries):
                     //   * 1.13 (proto 393-404): difficulty byte after dimension
                     //   * 1.14 (proto 477-498): difficulty REMOVED (moved to dedicated
                     //                           SetDifficulty packet, same as JoinGame)
                     //   * 1.15 (proto 573-578): hashed_seed i64 added (replaces
                     //                           difficulty slot but at a different offset)
    if proto < 477 {
        body.put_u8(0); // difficulty (1.13 only)
    } else if proto >= 573 {
        body.put_i64(0); // hashed_seed (1.15+)
    }
    body.put_u8(0); // gamemode = survival

    let level_type = "flat".to_string();
    let lt_bytes = level_type.as_bytes();
    VarInt(lt_bytes.len() as i32).encode(&mut body).ok()?;
    body.put_slice(lt_bytes);

    Some(EncodedPacket { id: pid, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    /// 1.13 (proto 393) JoinGame must be the legacy form — first 4
    /// bytes after the id are entity_id BE Int. No NBT, no codec.
    #[test]
    fn join_game_1_13_wire_shape() {
        let proto = 393_u32;
        let pkt = build_join_game_1_13_through_1_15(proto, "world").expect("must build");
        let body = pkt.body;
        // [i32 entity_id=0][u8 gamemode=3][i32 dimension=0][u8 difficulty=0]
        // [u8 max_players=20][VarInt("flat".len()=4)][b"flat"][u8 rdi=0]
        assert_eq!(&body[..4], &[0, 0, 0, 0], "entity_id");
        assert_eq!(body[4], 3, "gamemode = spectator");
        assert_eq!(&body[5..9], &[0, 0, 0, 0], "dimension i32 BE");
        assert_eq!(body[9], 0, "difficulty");
        assert_eq!(body[10], 20, "max_players");
        // VarInt(4) = single byte 0x04 then "flat" (4 bytes)
        assert_eq!(body[11], 4, "level_type length varint");
        assert_eq!(&body[12..16], b"flat");
        assert_eq!(body[16], 0, "reduced_debug_info");
        // No more bytes — no view_distance (1.14+), no enable_respawn_screen (1.15+).
        assert_eq!(body.len(), 17, "exact 1.13 wire size");
    }

    /// 1.14 (proto 477) appends a VarInt view_distance between
    /// level_type and reduced_debug_info.
    #[test]
    fn join_game_1_14_appends_view_distance() {
        let proto = 477_u32;
        let pkt = build_join_game_1_13_through_1_15(proto, "world").expect("must build");
        // 1.14 layout (no difficulty, view_distance added):
        //   [i32 entity_id][u8 gamemode][i32 dimension][u8 max_players]
        //   [VarInt 4]["flat"][VarInt 8 view_distance][u8 reduced_debug]
        //
        // 4 + 1 + 4 + 1 + 1 + 4 + 1 + 1 = 17 bytes total.
        // 1.13 was 17 bytes too (it had difficulty but no view_distance);
        // the two changes cancel out at the size level — but the
        // STRUCTURE differs: difficulty byte at position 9 in 1.13 is
        // replaced by max_players in 1.14 (and max_players shifts up).
        assert_eq!(
            pkt.body.len(),
            17,
            "1.14 body — no difficulty, has view_distance"
        );
        // Field positions:
        assert_eq!(&pkt.body[..4], &[0, 0, 0, 0], "entity_id");
        assert_eq!(pkt.body[4], 3, "gamemode = spectator");
        assert_eq!(&pkt.body[5..9], &[0, 0, 0, 0], "dimension");
        assert_eq!(
            pkt.body[9], 20,
            "max_players (no difficulty before it on 1.14)"
        );
        assert_eq!(pkt.body[10], 4, "level_type VarInt length");
        assert_eq!(&pkt.body[11..15], b"flat");
        assert_eq!(pkt.body[15], 8, "view_distance VarInt");
        assert_eq!(pkt.body[16], 0, "reduced_debug_info");
    }

    /// 1.15 (proto 573) drops difficulty, adds i64 hashed_seed right
    /// after the dimension field, and adds enable_respawn_screen at
    /// the end.
    #[test]
    fn join_game_1_15_drops_difficulty_adds_hashed_seed() {
        let proto = 573_u32;
        let pkt = build_join_game_1_13_through_1_15(proto, "world").expect("must build");
        let body = &pkt.body;
        // Layout: [i32 entity_id][u8 gamemode][i32 dimension]
        //         [i64 hashed_seed][u8 max_players][VarInt 4]["flat"]
        //         [VarInt 8 view_distance][u8 rdi][u8 enable_respawn]
        assert_eq!(&body[..4], &[0, 0, 0, 0]);
        assert_eq!(body[4], 3);
        assert_eq!(&body[5..9], &[0, 0, 0, 0]);
        assert_eq!(&body[9..17], &[0; 8], "hashed_seed i64 BE");
        assert_eq!(body[17], 20, "max_players");
        assert_eq!(body[18], 4);
        assert_eq!(&body[19..23], b"flat");
        assert_eq!(body[23], 8, "view_distance");
        assert_eq!(body[24], 0, "reduced_debug_info");
        assert_eq!(body[25], 1, "enable_respawn_screen = true");
        assert_eq!(body.len(), 26);
    }
}
