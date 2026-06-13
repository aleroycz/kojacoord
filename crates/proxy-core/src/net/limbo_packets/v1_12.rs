//! Limbo packets for the v1_12_x canonical bucket (1.9 – 1.12.2).

use bytes::{BufMut, BytesMut};
use kojacoord_protocol::codec::Encode;
use kojacoord_protocol::types::VarInt;
use kojacoord_protocol::versions::v1_12_x::play as p;
use uuid::Uuid;

use super::{encode, EncodedPacket, LimboPackets, PlayerPos, SoundParams};

pub struct V1_12;

impl LimboPackets for V1_12 {
    fn join_game(&self, proto: u32, _world_name: &str) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundJoinGame {
                entity_id: 0,
                gamemode: 0x03,
                dimension: 0,
                difficulty: 0,
                max_players: 20,
                level_type: "flat".to_string(),
                reduced_debug_info: false,
                for_proto: proto,
            },
        )
    }

    fn respawn(&self, proto: u32, _world_name: &str) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundRespawn {
                dimension: 0,
                difficulty: 0,
                game_mode: 0,
                level_type: "flat".to_string(),
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
            p::ClientboundChatMessage {
                json_message: json_message.to_owned(),
                position: 1,
            },
        )
    }

    fn note_sound(&self, _proto: u32, _pos: SoundParams) -> Option<EncodedPacket> {
        None
    }

    fn bossbar_add(&self, proto: u32, uuid: Uuid, title: &str) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundBossBar {
                uuid,
                action: p::BossBarAction::Add {
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
            p::ClientboundBossBar {
                uuid,
                action: p::BossBarAction::Remove,
            },
        )
    }

    fn keepalive(&self, proto: u32, id: i64) -> Option<EncodedPacket> {
        // Wire type for KeepAlive depends on `proto`:
        //   1.8 – 1.12.1 (47 ≤ proto ≤ 339) → VarInt
        //   1.12.2 onward (proto ≥ 340)     → Long (i64)
        // The struct dispatches internally — see v1_12_x::play::ClientboundKeepAlive.
        encode(
            proto,
            p::ClientboundKeepAlive {
                keep_alive_id: id,
                for_proto: proto,
            },
        )
    }

    fn brand(&self, proto: u32, brand: &str) -> Option<EncodedPacket> {
        // 1.12.x and earlier still use the legacy `MC|Brand` channel
        // name. The `minecraft:brand` flattening landed in 1.13. Pre-1.13
        // clients ignore plugin messages with the new name (and some
        // Forge stacks crash decoding the data with the wrong handler
        // max-length), so we have to keep the old name here.
        let channel = if proto >= 393 {
            "minecraft:brand"
        } else {
            "MC|Brand"
        };
        let mut data = BytesMut::new();
        VarInt(brand.len() as i32).encode(&mut data).ok()?;
        data.put_slice(brand.as_bytes());
        encode(
            proto,
            kojacoord_protocol::versions::v1_20_x::play::ClientboundPluginMessage {
                channel: channel.to_owned(),
                data: data.to_vec(),
            },
        )
    }
}
