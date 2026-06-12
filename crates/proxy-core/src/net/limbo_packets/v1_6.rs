//! Limbo packets for 1.6.x (pre-netty). Most are absent — 1.6 has no
//! configuration phase, no JoinGame in this shape, etc.

use kojacoord_protocol::versions::v1_6_x::play as p;
use uuid::Uuid;

use super::{encode, EncodedPacket, LimboPackets, PlayerPos, SoundParams};

pub struct V1_6;

impl LimboPackets for V1_6 {
    fn join_game(&self, _proto: u32, _world_name: &str) -> Option<EncodedPacket> {
        // Pre-netty's Packet1Login was already sent by `connection.rs`
        // at LoginSuccess time (the 1.6 client treats Packet1Login as
        // both LoginSuccess AND JoinGame — there's no separate
        // play-state entry packet). Sending a second one here would
        // make the client see two world-entry frames back-to-back;
        // some launchers tolerate it, others reset the entity table
        // and re-render the dirt-screen.
        //
        // The post-LoginRequest essentials (SpawnPosition / TimeUpdate
        // / UpdateHealth / PlayerAbilities / HeldItemChange /
        // PlayerPosition) are still emitted by the per-method calls
        // below — only the JoinGame slot is intentionally a no-op.
        None
    }

    fn respawn(&self, proto: u32, _world_name: &str) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundRespawn {
                dimension: 0,
                difficulty: 0,
                gamemode: 0,
                world_height: 256,
                level_type: "default".to_string(),
            },
        )
    }

    fn player_abilities(&self, proto: u32) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundPlayerAbilities {
                flags: 0x04,
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
        _teleport_id: i32,
    ) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundPlayerPosition {
                x: pos.x,
                y: pos.y,
                stance: pos.y + 1.62,
                z: pos.z,
                yaw: pos.yaw,
                pitch: pos.pitch,
                on_ground: true,
            },
        )
    }

    fn chat(&self, proto: u32, json_message: &str) -> Option<EncodedPacket> {
        // 1.6.x **DOES** parse chat messages as JSON.
        //
        // Mojang introduced `MessageComponentSerializer` (the Gson-based
        // chat component deserialiser) in 1.6.0. The Notchian 1.6.4
        // client's `NetClientHandler.handleChat` calls
        // `ChatMessageComponent.func_111078_c(message)` which is
        // `Gson.fromJson(message, ChatMessageComponent.class)` — and
        // the deserialiser explicitly casts the root to `JsonObject`,
        // so anything that isn't an object (a bare string, a number)
        // triggers `ClassCastException: JsonPrimitive cannot be cast
        // to JsonObject` and crashes the client with
        // `Deserializing Message`.
        //
        // Earlier code here converted the JSON to plaintext via
        // `plaintext_from_chat_json` on the (incorrect) belief that
        // pre-netty used plaintext — that comment dated to 1.5.2 and
        // never got updated when the bucket was repurposed for 1.6.
        // Send the JSON through verbatim instead.
        encode(
            proto,
            p::ClientboundChatMessage {
                message: json_message.to_owned(),
            },
        )
    }

    fn note_sound(&self, _proto: u32, _pos: SoundParams) -> Option<EncodedPacket> {
        // 1.6.x sound packet shape isn't in our typed surface; skip.
        None
    }

    fn bossbar_add(&self, _proto: u32, _uuid: Uuid, _title: &str) -> Option<EncodedPacket> {
        None // bossbars are 1.9+
    }

    fn bossbar_remove(&self, _proto: u32, _uuid: Uuid) -> Option<EncodedPacket> {
        None
    }

    fn keepalive(&self, proto: u32, id: i64) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundKeepAlive {
                keep_alive_id: id as i32,
            },
        )
    }

    fn brand(&self, _proto: u32, _brand: &str) -> Option<EncodedPacket> {
        // 1.6.x has no plugin-message brand channel.
        None
    }

    fn spawn_position(&self, proto: u32, pos: PlayerPos) -> Option<EncodedPacket> {
        // Round the spawn anchor to the nearest block — the field is
        // i32, but limbo's PlayerPos uses f64 for the position packet
        // it also drives.
        encode(
            proto,
            p::ClientboundSpawnPosition {
                x: pos.x as i32,
                y: pos.y as i32,
                z: pos.z as i32,
            },
        )
    }

    fn time_update(&self, proto: u32) -> Option<EncodedPacket> {
        // `time_of_day` modulo 24000 controls the day-night cycle.
        // Setting it to 6000 (high noon) makes limbo render in
        // daylight regardless of whatever the backend last sent.
        encode(
            proto,
            p::ClientboundTimeUpdate {
                world_age: 0,
                time_of_day: 6000,
            },
        )
    }

    fn update_health(&self, proto: u32) -> Option<EncodedPacket> {
        // Full HP / food / saturation. Without this the 1.6.4 client
        // renders the respawn overlay and refuses input.
        encode(
            proto,
            p::ClientboundUpdateHealth {
                health: 20.0,
                food: 20,
                food_saturation: 5.0,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full pre-netty limbo entry sequence at the encoder layer.
    ///
    /// Mirrors the order `LimboHandler::run_inner` emits for proto 78
    /// (1.6.4): JoinGame → SpawnPosition → TimeUpdate → UpdateHealth →
    /// PlayerAbilities → HeldItemChange → PlayerPosition → Chat →
    /// KeepAlive. Every step must produce `Some(EncodedPacket)` with
    /// the HexaCord-canonical packet id; if any step regresses to
    /// `None` the 1.6.4 client gets stuck before world entry.
    ///
    /// The pre-netty no-op packets (note_sound / brand / bossbars)
    /// stay `None` — pre-1.7 has no equivalent on the wire.
    #[test]
    fn limbo_entry_sequence_proto_78() {
        const PROTO: u32 = 78;
        let v = V1_6;

        // join_game intentionally returns None for pre-netty — the
        // Packet1Login that does the world-entry work is sent by
        // `connection.rs::send_login_success` at LoginSuccess time,
        // before limbo runs. See the comment on V1_6::join_game.
        assert!(
            v.join_game(PROTO, "kojacoord:limbo").is_none(),
            "1.6.x limbo must not duplicate Packet1Login — connection.rs already sent it"
        );

        let sp = v
            .spawn_position(
                PROTO,
                PlayerPos {
                    x: 0.0,
                    y: 256.0,
                    z: 0.0,
                    yaw: 0.0,
                    pitch: 0.0,
                },
            )
            .expect("SpawnPosition must build");
        assert_eq!(sp.id, 0x06, "Packet6SpawnPosition id");
        assert_eq!(sp.body.len(), 12, "3 × i32 BE");

        let tu = v.time_update(PROTO).expect("TimeUpdate must build");
        assert_eq!(tu.id, 0x04, "Packet4UpdateTime id");
        assert_eq!(tu.body.len(), 16, "2 × i64 BE");

        let uh = v.update_health(PROTO).expect("UpdateHealth must build");
        assert_eq!(uh.id, 0x08, "Packet8UpdateHealth id");
        assert_eq!(uh.body.len(), 10, "f32 + i16 + f32");

        let pa = v
            .player_abilities(PROTO)
            .expect("PlayerAbilities must build");
        assert_eq!(
            pa.id, 0xCA,
            "Packet202PlayerAbilities id (decimal 202 = 0xCA)"
        );

        let hic = v
            .held_item_change(PROTO)
            .expect("HeldItemChange must build");
        assert_eq!(hic.id, 0x10, "Packet16BlockItemSwitch id");

        let pp = v
            .player_position(
                PROTO,
                PlayerPos {
                    x: 0.0,
                    y: 256.0,
                    z: 0.0,
                    yaw: 0.0,
                    pitch: 0.0,
                },
                0,
            )
            .expect("PlayerPosition must build");
        assert_eq!(pp.id, 0x0D, "Packet13PlayerLookMove id");

        let chat = v.chat(PROTO, r#"{"text":"hi"}"#).expect("Chat must build");
        assert_eq!(chat.id, 0x03, "Packet3Chat id");

        let ka = v.keepalive(PROTO, 42).expect("KeepAlive must build");
        assert_eq!(ka.id, 0x00, "Packet0KeepAlive id");

        // Pre-netty has no equivalent for these; default impls return None.
        assert!(
            v.brand(PROTO, "Kojacoord").is_none(),
            "1.6.x has no brand channel"
        );
        assert!(
            v.note_sound(
                PROTO,
                SoundParams {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                    volume: 1.0,
                    pitch: 1.0
                }
            )
            .is_none(),
            "1.6.x note_sound is unmapped"
        );
        assert!(
            v.bossbar_add(PROTO, Uuid::nil(), "x").is_none(),
            "bossbars are 1.9+"
        );
    }

    /// Defensive: the modern bucket impls (V1_8/V1_12/etc) MUST NOT
    /// accidentally start emitting pre-netty essentials. The default
    /// trait impls return None; this test pins that for the
    /// canonical V1_8 bucket. If a future impl overrides them by
    /// mistake, modern clients would see duplicate spawn-position /
    /// time / health packets after JoinGame, which some launchers
    /// reject.
    #[test]
    fn modern_buckets_dont_emit_pre_netty_essentials() {
        use crate::limbo_packets::v1_8::V1_8;
        const PROTO: u32 = 47;
        let v = V1_8;
        assert!(v
            .spawn_position(
                PROTO,
                PlayerPos {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                    yaw: 0.0,
                    pitch: 0.0
                }
            )
            .is_none());
        assert!(v.time_update(PROTO).is_none());
        assert!(v.update_health(PROTO).is_none());
    }
}
