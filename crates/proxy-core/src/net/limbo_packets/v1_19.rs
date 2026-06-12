//! Limbo packets for the v1_19_x canonical bucket (1.17 – 1.19.4).
//!
//! 1.17 and 1.18 (proto 755-758) use an NBT dimension shape that we
//! don't synthesise. Methods affected by that gate (Login, Respawn,
//! SystemChat) return `None` for those protos.

use bytes::{BufMut, BytesMut};
use kojacoord_protocol::codec::{Encode, PacketId};
use kojacoord_protocol::types::VarInt;
use kojacoord_protocol::versions::v1_19_x::play as p;
use uuid::Uuid;

use super::{encode, EncodedPacket, LimboPackets, PlayerPos, SoundParams};

pub struct V1_19;

impl LimboPackets for V1_19 {
    fn join_game(&self, proto: u32, world_name: &str) -> Option<EncodedPacket> {
        // The V1_19 limbo bucket spans 1.17 - 1.19.4 (protos 755 - 762),
        // and the JoinGame wire shape changed twice inside that window:
        //
        //   proto 755 - 756 (1.17 / 1.17.1)   : NBT dimension, NO
        //                                       simulation_distance,
        //                                       NO death_location
        //   proto 757 - 758 (1.18 / 1.18.2)   : NBT dimension, HAS
        //                                       simulation_distance,
        //                                       NO death_location
        //   proto 759 - 763 (1.19 / 1.19.4)   : String Identifier
        //                                       dimension, HAS
        //                                       simulation_distance,
        //                                       HAS death_location
        //
        // The typed `ClientboundLogin` struct above models the proto-759
        // shape; we hand-encode the 1.17/1.18 variant here so the limbo
        // emits a packet a vanilla 1.17/1.18 client can actually parse.
        // Without this branch those clients hung on the dirt-screen and
        // disconnected by keepalive timeout. Sourced from BungeeCord
        // `Login.java::read` + minecraft.wiki Java_Edition_protocol
        // §Join_Game (proto 755 / 757 entries).
        //
        // 1.20.2+ (proto 764+) moved registries to the configuration
        // phase entirely — those use the v1_20::V1_20 limbo bucket,
        // never this one.
        if (755..=758).contains(&proto) {
            return build_join_game_1_17_or_1_18(proto, world_name);
        }
        if !(759..=763).contains(&proto) {
            return None;
        }
        // `registry_codec` is a self-framing NBT tag. An empty `Vec<u8>`
        // would underflow the client's NBT reader. Reuse the synthesised
        // codec helper (a minimal dimension_type + biome registry).
        let registry_codec = crate::protocol::build_dimension_codec_for_proto(proto).ok()?;
        encode(
            proto,
            p::ClientboundLogin {
                entity_id: 0,
                is_hardcore: false,
                game_mode: 3,
                previous_game_mode: -1,
                dimensions: vec![world_name.to_owned()],
                registry_codec,
                dimension_type: "minecraft:overworld".to_owned(),
                dimension_name: world_name.to_owned(),
                hashed_seed: 0,
                max_players: VarInt(20),
                chunk_radius: VarInt(8),
                simulation_distance: VarInt(8),
                reduced_debug_info: false,
                enable_respawn_screen: true,
                is_debug: false,
                is_flat: true,
                death_location: None,
            },
        )
    }

    fn respawn(&self, proto: u32, world_name: &str) -> Option<EncodedPacket> {
        // 1.17/1.18 Respawn is shape-identical to JoinGame's dimension
        // half: NBT dimension + Identifier dimension_name + the trailing
        // i64/byte/byte/bool/bool block. data_kept and death_location
        // (1.19+ additions) MUST be omitted for proto < 759 or the
        // client reads them as part of the next packet's framing.
        if (755..=758).contains(&proto) {
            return build_respawn_1_17_or_1_18(proto, world_name);
        }
        if proto < 759 {
            return None;
        }
        encode(
            proto,
            p::ClientboundRespawn {
                dimension_type: "minecraft:overworld".to_owned(),
                dimension_name: world_name.to_owned(),
                hashed_seed: 0,
                game_mode: 0,
                previous_game_mode: -1,
                is_debug: false,
                is_flat: true,
                data_kept: 0,
                death_location: None,
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
        encode(proto, p::ClientboundSetCarriedItem { slot: 0 })
    }

    fn player_position(
        &self,
        proto: u32,
        pos: PlayerPos,
        teleport_id: i32,
    ) -> Option<EncodedPacket> {
        // 1.17 / 1.17.1 / 1.18 / 1.18.2 / 1.19 / 1.19.1 / 1.19.2 /
        // 1.19.3 (proto 755 - 762) carry a trailing
        // `dismount_vehicle: bool` byte after `teleport_id`. Mojang
        // added it at 1.17 (per ViaVersion
        // `EntityPacketRewriter1_17` line 144: `create(Types.BOOLEAN,
        // false); // Dismount vehicle`) and removed it at 1.19.4
        // (per `EntityPacketRewriter1_19_4` line 93:
        // `if (wrapper.read(Types.BOOLEAN)) { // Dismount vehicle`).
        //
        // The v1_19 typed encoder doesn't emit the byte, so without
        // this guard the 1.17 client expects 36 wire bytes and gets
        // 35 — exact match for the user-reported
        // `readerIndex(35) + length(1) exceeds writerIndex(35)`
        // disconnect.
        if (755..=762).contains(&proto) {
            use kojacoord_protocol::codec::PacketId;
            let pid = p::ClientboundPlayerPosition::packet_id(proto);
            if pid == 0xFF {
                return None;
            }
            let mut body = BytesMut::new();
            body.put_f64(pos.x);
            body.put_f64(pos.y);
            body.put_f64(pos.z);
            body.put_f32(pos.yaw);
            body.put_f32(pos.pitch);
            body.put_u8(0); // flags
            VarInt(teleport_id).encode(&mut body).ok()?;
            body.put_u8(0); // dismount_vehicle = false
            return Some(EncodedPacket { id: pid, body });
        }
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
        // 1.17 / 1.18 (proto 755-758) speak the *legacy* ChatMessage
        // shape: String JSON + i8 position + UUID sender. SystemChat
        // (which collapses to String content + bool overlay) only lands
        // at proto 759. Borrow the v1_16_x typed packet for the legacy
        // shape — it's wire-identical between 1.16 and 1.18.2.
        if (755..=758).contains(&proto) {
            return encode(
                proto,
                kojacoord_protocol::versions::v1_16_x::play::ClientboundChatMessage {
                    json_message: json_message.to_owned(),
                    position: 1,
                    sender: Uuid::nil(),
                },
            );
        }
        if proto < 759 {
            return None;
        }
        encode(
            proto,
            p::ClientboundSystemChat {
                content: json_message.to_owned(),
                overlay: false,
            },
        )
    }

    fn note_sound(&self, proto: u32, pos: SoundParams) -> Option<EncodedPacket> {
        // Sound packet wire shape across this canonical bucket:
        //   proto 755 - 758 (1.17 / 1.18.x): legacy NamedSoundEffect
        //       [Identifier sound_name][VarInt sound_category]
        //       [i32 x*8][i32 y*8][i32 z*8][f32 volume][f32 pitch]
        //   proto 759 - 760 (1.19 / 1.19.1.2.0): + `seed: i64` trailer
        //   proto 761+ (1.19.3+): + `sound_type` VarInt prefix +
        //                          `seed` trailer
        //
        // The v1_21_x typed encoder writes the 1.19.3+ shape with
        // both extras. Sending that to a 1.17 client shifts every
        // position-and-volume field by 5 bytes (sound_type VarInt(0)
        // = 1 byte) → the client reads our sound_category byte as
        // `effect_pos_x` and so on; eventually a non-existent
        // SoundCategory index lookup fires
        // `ArrayIndexOutOfBoundsException: Index 24 out of bounds for
        // length 10` (the 1.17 SoundCategory enum has 10 variants).
        if (755..=758).contains(&proto) {
            return encode(
                proto,
                kojacoord_protocol::versions::v1_16_x::play::ClientboundNamedSoundEffect {
                    sound_name: "minecraft:music_disc.cat".to_owned(),
                    sound_category: VarInt(2),
                    effect_position_x: (pos.x * 8.0) as i32,
                    effect_position_y: (pos.y * 8.0) as i32,
                    effect_position_z: (pos.z * 8.0) as i32,
                    volume: pos.volume,
                    pitch: pos.pitch,
                },
            );
        }
        encode(
            proto,
            kojacoord_protocol::versions::v1_21_x::play::ClientboundSound {
                sound_name: "minecraft:music_disc.cat".to_owned(),
                sound_category: VarInt(2),
                sound_type: VarInt(0),
                effect_pos_x: (pos.x * 8.0) as i32,
                effect_pos_y: (pos.y * 8.0) as i32,
                effect_pos_z: (pos.z * 8.0) as i32,
                volume: pos.volume,
                pitch: pos.pitch,
                seed: 0,
            },
        )
    }

    fn bossbar_add(&self, proto: u32, uuid: Uuid, title: &str) -> Option<EncodedPacket> {
        encode(
            proto,
            kojacoord_protocol::versions::v1_20_x::play::ClientboundBossBar {
                uuid,
                action: kojacoord_protocol::versions::v1_20_x::play::BossBarAction::Add {
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
            kojacoord_protocol::versions::v1_20_x::play::ClientboundBossBar {
                uuid,
                action: kojacoord_protocol::versions::v1_20_x::play::BossBarAction::Remove,
            },
        )
    }

    fn keepalive(&self, proto: u32, id: i64) -> Option<EncodedPacket> {
        encode(proto, p::ClientboundKeepAlive { id })
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

/// Hand-encode the 1.17 / 1.18 JoinGame.
///
/// Wire shape (BungeeCord `Login.java::read` 1.17 / 1.18 branches +
/// minecraft.wiki Java_Edition_protocol §Join_Game):
///
/// ```text
/// [i32 entity_id] [bool is_hardcore] [u8 game_mode] [i8 previous_game_mode]
/// [VarInt dim_count + N × String world_name]
/// [NBT registry_codec]
/// [NBT dimension_type]                  ; ← NBT compound, NOT Identifier
/// [String world_name]
/// [i64 hashed_seed] [VarInt max_players] [VarInt view_distance]
/// [VarInt simulation_distance ← 1.18 only, 757/758]
/// [bool reduced_debug_info] [bool enable_respawn_screen]
/// [bool is_debug] [bool is_flat]
/// ```
fn build_join_game_1_17_or_1_18(proto: u32, world_name: &str) -> Option<EncodedPacket> {
    let pid = p::ClientboundLogin::packet_id(proto);
    if pid == 0xFF {
        return None;
    }
    let registry_codec = crate::protocol::build_dimension_codec_for_proto(proto).ok()?;
    let dimension_nbt = kojacoord_protocol::dimension_codec::dimension_type_nbt_for_proto(
        "minecraft:overworld",
        proto,
    )
    .ok()?;

    let mut body = BytesMut::new();
    body.put_i32(0); // entity_id
    body.put_u8(0); // is_hardcore
    body.put_u8(3); // game_mode = spectator
    body.put_i8(-1); // previous_game_mode

    // dimensions: VarInt count + each String
    VarInt(1).encode(&mut body).ok()?;
    let name_bytes = world_name.as_bytes();
    VarInt(name_bytes.len() as i32).encode(&mut body).ok()?;
    body.put_slice(name_bytes);

    body.put_slice(&registry_codec); // NBT-framed, self-delimited
    body.put_slice(&dimension_nbt); // NBT compound (the 1.17/1.18 dimension)

    VarInt(name_bytes.len() as i32).encode(&mut body).ok()?;
    body.put_slice(name_bytes);

    body.put_i64(0); // hashed_seed
    VarInt(20).encode(&mut body).ok()?; // max_players
    VarInt(8).encode(&mut body).ok()?; // view_distance / chunk_radius

    // simulation_distance only exists from 1.18 (proto 757) onward.
    if proto >= 757 {
        VarInt(8).encode(&mut body).ok()?;
    }
    body.put_u8(0); // reduced_debug_info = false
    body.put_u8(1); // enable_respawn_screen = true
    body.put_u8(0); // is_debug = false
    body.put_u8(1); // is_flat = true

    Some(EncodedPacket { id: pid, body })
}

/// Hand-encode the 1.17 / 1.18 Respawn.
///
/// Wire shape:
/// ```text
/// [NBT dimension_type] [String world_name]
/// [i64 hashed_seed] [u8 game_mode] [i8 previous_game_mode]
/// [bool is_debug] [bool is_flat] [bool copy_metadata]
/// ```
/// The 1.19+ `data_kept` byte and `death_location` optional are absent.
fn build_respawn_1_17_or_1_18(proto: u32, world_name: &str) -> Option<EncodedPacket> {
    let pid = p::ClientboundRespawn::packet_id(proto);
    if pid == 0xFF {
        return None;
    }
    let dimension_nbt = kojacoord_protocol::dimension_codec::dimension_type_nbt_for_proto(
        "minecraft:overworld",
        proto,
    )
    .ok()?;

    let mut body = BytesMut::new();
    body.put_slice(&dimension_nbt);

    let name_bytes = world_name.as_bytes();
    VarInt(name_bytes.len() as i32).encode(&mut body).ok()?;
    body.put_slice(name_bytes);

    body.put_i64(0); // hashed_seed
    body.put_u8(0); // game_mode = survival
    body.put_i8(-1); // previous_game_mode
    body.put_u8(0); // is_debug
    body.put_u8(1); // is_flat
    body.put_u8(0); // copy_metadata = false

    Some(EncodedPacket { id: pid, body })
}

#[cfg(test)]
mod ship_check {
    //! PlayerPosition body-length pins. Mojang's `dismount_vehicle`
    //! trailing bool lived on the wire from proto 755 (1.17) through
    //! proto 762 (1.19.3), then was removed at 1.19.4 (proto 763).
    //! These tests fail if the body length doesn't match the
    //! per-proto spec.
    use super::*;

    fn body_len(proto: u32) -> usize {
        let v = V1_19;
        let pos = PlayerPos {
            x: 0.0,
            y: 256.0,
            z: 0.0,
            yaw: 0.0,
            pitch: 0.0,
        };
        v.player_position(proto, pos, 1)
            .expect("must build")
            .body
            .len()
    }

    /// PlayerPosition body field sum without `dismount_vehicle`:
    /// `f64*3 + f32*2 + u8 flags + VarInt(1)` = 24 + 8 + 1 + 1 = 34 bytes.
    #[test]
    fn proto_754_player_position_body_is_34_bytes_no_dismount() {
        // 1.16.5 — pre-1.17 era, no dismount_vehicle.
        assert_eq!(body_len(754), 34);
    }

    #[test]
    fn proto_755_player_position_body_is_35_bytes_with_dismount() {
        // 1.17 — this turn's reported bug. Adds the dismount_vehicle byte.
        assert_eq!(body_len(755), 35, "1.17 must include dismount_vehicle");
    }

    #[test]
    fn proto_758_player_position_body_is_35_bytes_with_dismount() {
        // 1.18.2 — still in the dismount window.
        assert_eq!(body_len(758), 35);
    }

    #[test]
    fn proto_762_player_position_body_is_35_bytes_with_dismount() {
        // 1.19.3 — last proto with dismount_vehicle.
        assert_eq!(body_len(762), 35);
    }

    #[test]
    fn proto_763_player_position_body_is_34_bytes_no_dismount() {
        // 1.19.4 — Mojang removed dismount_vehicle here.
        assert_eq!(body_len(763), 34);
    }

    fn sound_body_len(proto: u32) -> usize {
        let v = V1_19;
        let s = SoundParams {
            x: 0.0,
            y: 256.0,
            z: 0.0,
            volume: 1.0,
            pitch: 1.0,
        };
        v.note_sound(proto, s).expect("must build").body.len()
    }

    /// 1.17 / 1.18 Sound body = `[VarInt(24) "minecraft:music_disc.cat"]`
    /// `[VarInt cat=2][i32×3][f32×2]` = 1 + 24 + 1 + 12 + 8 = 46.
    /// Specifically MUST NOT include `sound_type` VarInt prefix or
    /// `seed` i64 trailer (those are 1.19.3+).
    #[test]
    fn proto_755_sound_body_is_46_bytes_no_seed_no_sound_type() {
        assert_eq!(
            sound_body_len(755),
            46,
            "1.17 Sound must use legacy NamedSoundEffect shape (no sound_type, no seed)"
        );
    }

    #[test]
    fn proto_758_sound_body_is_46_bytes_no_seed_no_sound_type() {
        assert_eq!(sound_body_len(758), 46);
    }
}
