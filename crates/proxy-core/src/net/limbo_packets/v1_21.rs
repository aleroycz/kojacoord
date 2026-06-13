//! Limbo packets for the v1_21_x canonical bucket (1.21 – 1.21.11).

use bytes::{BufMut, BytesMut};
use kojacoord_protocol::codec::Encode;
use kojacoord_protocol::types::VarInt;
use kojacoord_protocol::versions::v1_21_x::play as p;
use uuid::Uuid;

use super::{encode, EncodedPacket, LimboPackets, PlayerPos, SoundParams};

pub struct V1_21;

impl LimboPackets for V1_21 {
    fn join_game(&self, proto: u32, world_name: &str) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundLogin {
                entity_id: 0,
                is_hardcore: false,
                dimension_names: vec![world_name.to_owned()],
                max_players: VarInt(20),
                view_distance: VarInt(8),
                simulation_distance: VarInt(8),
                reduced_debug_info: false,
                enable_respawn_screen: true,
                do_limited_crafting: false,
                dimension_type: VarInt(0),
                dimension_name: world_name.to_owned(),
                hashed_seed: 0,
                game_mode: 3,
                previous_game_mode: -1,
                is_debug: false,
                is_flat: true,
                death_location: None,
                portal_cooldown: VarInt(0),
                // `sea_level` is on the wire only from proto 768 (1.21.2+).
                // Proto 767 (1.21 / 1.21.1) must omit it.
                sea_level: if proto >= 768 { Some(VarInt(63)) } else { None },
                // `secure_profile` has been mandatory since proto 766
                // (1.20.5+); always present for the V1_21 bucket.
                secure_profile: false,
            },
        )
    }

    fn respawn(&self, proto: u32, world_name: &str) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundRespawn {
                dimension_type: VarInt(0),
                dimension_name: world_name.to_owned(),
                hashed_seed: 0,
                game_mode: 0,
                previous_game_mode: -1,
                is_debug: false,
                is_flat: true,
                data_kept: 0,
                death_location: None,
                portal_cooldown: VarInt(0),
                sea_level: VarInt(0),
            },
        )
    }

    fn player_abilities(&self, proto: u32) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundPlayerAbilities {
                raw: vec![0x06, 0, 0],
            },
        )
    }

    fn held_item_change(&self, proto: u32) -> Option<EncodedPacket> {
        encode(proto, p::ClientboundSetCarriedItem { raw: vec![0] })
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
        encode(
            proto,
            p::ClientboundSystemChat {
                json_message: json_message.to_owned(),
                overlay: false,
            },
        )
    }

    fn note_sound(&self, proto: u32, pos: SoundParams) -> Option<EncodedPacket> {
        // `Holder<SoundEvent>`: VarInt sound_id (0 = inline) + Identifier
        // name + `option<f32> fixed_range` (leading bool) + category +
        // pos + vol + pitch + seed. The typed `ClientboundSound` encoder
        // omits `fixed_range`, over-running `seed`. Hand-encode it.
        let id = kojacoord_protocol::registry::cb_play(proto, "ClientboundSound");
        if id == 0xFF {
            return None;
        }
        let mut body = BytesMut::new();
        VarInt(0).encode(&mut body).ok()?; // sound_id 0 = inline event
        let name = b"minecraft:music_disc.cat";
        VarInt(name.len() as i32).encode(&mut body).ok()?;
        body.put_slice(name);
        body.put_u8(0); // fixed_range option: absent
        VarInt(2).encode(&mut body).ok()?; // sound_category
        body.put_i32((pos.x * 8.0) as i32);
        body.put_i32((pos.y * 8.0) as i32);
        body.put_i32((pos.z * 8.0) as i32);
        body.put_f32(pos.volume);
        body.put_f32(pos.pitch);
        body.put_i64(0); // seed
        Some(EncodedPacket { id, body })
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

    fn set_center_chunk(&self, proto: u32) -> Option<EncodedPacket> {
        // Ids per ViaVersion `ClientboundPackets1_21*` ordinals.
        let id: u8 = match proto {
            767 => 0x54,             // 1.21 / 1.21.1
            768..=769 => 0x58,       // 1.21.2 / 1.21.3 / 1.21.4
            770..=772 => 0x57, // 1.21.5 / 1.21.6 / 1.21.7 / 1.21.8
            773..=774 => 0x5c,       // 1.21.9 / 1.21.10 / 1.21.11
            _ => return None,
        };
        let mut body = BytesMut::new();
        VarInt(0).encode(&mut body).ok()?;
        VarInt(0).encode(&mut body).ok()?;
        Some(EncodedPacket { id, body })
    }

    fn chunk_data(&self, proto: u32) -> Option<EncodedPacket> {
        let id = kojacoord_protocol::registry::cb_play(proto, "ClientboundLevelChunkWithLight");
        if id == 0xFF {
            return None;
        }
        // 24 sections (384 high), no trust_edges. Heightmaps: nameless
        // NBT through 1.21.4 (769), then a typed array from 1.21.5 (770).
        let hm = if proto >= 770 {
            super::HeightmapFmt::Array
        } else {
            super::HeightmapFmt::AnonNbt
        };
        let body = super::void_chunk_body(24, false, hm);
        Some(EncodedPacket { id, body })
    }

    fn chunk_batch_start(&self, proto: u32) -> Option<EncodedPacket> {
        let id: u8 = match proto {
            767..=769 => 0x0d,
            770..=774 => 0x0c,
            _ => return None,
        };
        Some(EncodedPacket {
            id,
            body: BytesMut::new(),
        })
    }

    fn chunk_batch_finished(&self, proto: u32, batch_size: i32) -> Option<EncodedPacket> {
        let id: u8 = match proto {
            767..=769 => 0x0c,
            770..=774 => 0x0b,
            _ => return None,
        };
        let mut body = BytesMut::new();
        VarInt(batch_size).encode(&mut body).ok()?;
        Some(EncodedPacket { id, body })
    }

    fn start_wait_chunks_event(&self, proto: u32) -> Option<EncodedPacket> {
        // GameEvent 13 — `[u8 event][f32 value]`.
        let id: u8 = match proto {
            767 => 0x22,             // 1.21 / 1.21.1
            768..=769 => 0x23,       // 1.21.2 / 1.21.3 / 1.21.4
            770..=772 => 0x22, // 1.21.5 / 1.21.6 / 1.21.7 / 1.21.8
            773..=774 => 0x26,       // 1.21.9 / 1.21.10 / 1.21.11
            _ => return None,
        };
        let mut body = BytesMut::new();
        body.put_u8(13);
        body.put_f32(0.0);
        Some(EncodedPacket { id, body })
    }
}
