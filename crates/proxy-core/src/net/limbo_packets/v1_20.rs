//! Limbo packets for the v1_20_x canonical bucket (1.20 – 1.20.6).

use bytes::{BufMut, BytesMut};
use kojacoord_protocol::codec::Encode;
use kojacoord_protocol::types::VarInt;
use kojacoord_protocol::versions::v1_20_x::play as p;
use uuid::Uuid;

use super::{encode, EncodedPacket, LimboPackets, PlayerPos, SoundParams};

pub struct V1_20;

impl LimboPackets for V1_20 {
    /// Constructs a Clientbound Join Game (login) packet for the 1.20 canonical protocol range.
    ///
    /// For protocol 763 (Minecraft 1.20 / 1.20.1) this hand-encodes the legacy JoinGame shape that
    /// includes the inline registry codec and the older field ordering. For all other supported
    /// 1.20-series protocol versions this produces a `p::ClientboundLogin` encoded packet with
    /// fields adjusted by protocol:
    /// - `do_limited_crafting` is present only when `proto >= 764`.
    /// - `dimension_type` is an identifier for `proto < 766` and a registry index for `proto >= 766`.
    /// - `secure_profile` is present only when `proto >= 766`.
    ///
    /// # Returns
    ///
    /// `Some(EncodedPacket)` containing the packet id and encoded body on success, or `None` if the
    /// packet id is unsupported for the given `proto` or if required encoding steps fail.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let v = V1_20;
    /// let pkt = v.join_game(764, "minecraft:overworld");
    /// assert!(pkt.is_some());
    /// ```
    fn join_game(&self, proto: u32, world_name: &str) -> Option<EncodedPacket> {
        // 1.20 / 1.20.1 (proto 763) predate the configuration phase, so
        // they still carry the registry codec INLINE in JoinGame — the
        // 1.19.4 shape plus a trailing `portal_cooldown` VarInt. The
        // typed `ClientboundLogin` below models only the 1.20.2+ compact
        // form (codec moved to config), so hand-encode 763 here. Field
        // order from minecraft-data `pc/1.20` loginPacket.
        if proto == 763 {
            use kojacoord_protocol::codec::PacketId;
            let pid = p::ClientboundLogin::packet_id(proto);
            if pid == 0xFF {
                return None;
            }
            let codec = crate::protocol::build_dimension_codec_for_proto(proto).ok()?;
            let mut body = BytesMut::new();
            body.put_i32(0); // entity_id
            body.put_u8(0); // is_hardcore
            body.put_u8(3); // game_mode = spectator
            body.put_i8(-1); // previous_game_mode
            VarInt(1).encode(&mut body).ok()?; // dimension count
            let name = world_name.as_bytes();
            VarInt(name.len() as i32).encode(&mut body).ok()?;
            body.put_slice(name);
            body.put_slice(&codec); // registry codec (self-framing NBT)
            let dt = b"minecraft:overworld";
            VarInt(dt.len() as i32).encode(&mut body).ok()?; // dimension_type
            body.put_slice(dt);
            VarInt(name.len() as i32).encode(&mut body).ok()?; // dimension_name
            body.put_slice(name);
            body.put_i64(0); // hashed_seed
            VarInt(20).encode(&mut body).ok()?; // max_players
            VarInt(8).encode(&mut body).ok()?; // view_distance
            VarInt(8).encode(&mut body).ok()?; // simulation_distance
            body.put_u8(0); // reduced_debug_info
            body.put_u8(1); // enable_respawn_screen
            body.put_u8(0); // is_debug
            body.put_u8(1); // is_flat
            body.put_u8(0); // has_death_location = false
            VarInt(0).encode(&mut body).ok()?; // portal_cooldown
            return Some(EncodedPacket { id: pid, body });
        }
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
                // `do_limited_crafting` was added in 1.20.2 (proto 764)
                // per BungeeCord `protocol/Login.java`:
                //   `if ( protocolVersion >= MINECRAFT_1_20_2 ) {
                //        limitedCrafting = buf.readBoolean();`
                // The Configuration-phase split also landed at 764, so
                // the entire post-1.20.2 Login(Play) compact form starts
                // here. 1.20-1.20.1 (763) do NOT carry it.
                do_limited_crafting: if proto >= 764 { Some(false) } else { None },
                // 1.20.2 / 1.20.4 (proto 764 / 765) expect an Identifier
                // here (`minecraft:overworld`); 1.20.5+ (proto 766) flipped
                // to a VarInt registry index. See DimensionTypeRef.
                dimension_type: if proto >= 766 {
                    p::DimensionTypeRef::Registry(VarInt(0))
                } else {
                    p::DimensionTypeRef::Identifier("minecraft:overworld".to_owned())
                },
                dimension_name: world_name.to_owned(),
                hashed_seed: 0,
                game_mode: 3,
                previous_game_mode: -1,
                is_debug: false,
                is_flat: true,
                death_location: None,
                portal_cooldown: VarInt(0),
                // `secure_profile` was added in proto 766 (1.20.5). For
                // 1.20-1.20.4 it must be absent. Per BungeeCord Login.java.
                secure_profile: if proto >= 766 { Some(false) } else { None },
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

    /// Constructs a system chat packet containing the provided JSON chat component.
    ///
    /// The packet will have the overlay flag set to `false`.
    ///
    /// # Parameters
    ///
    /// - `json_message`: JSON-formatted chat component string (for example, a serialized Minecraft chat component).
    ///
    /// # Returns
    ///
    /// `Some(EncodedPacket)` with the encoded system chat packet on success, `None` if the packet is not applicable for `proto` or if encoding fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let v = V1_20;
    /// let pkt = v.chat(764, "{\"text\":\"Hello world\"}");
    /// assert!(pkt.is_some());
    /// ```
    fn chat(&self, proto: u32, json_message: &str) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundSystemChat {
                content: json_message.to_owned(),
                overlay: false,
            },
        )
    }

    /// Constructs a clientbound sound packet for the v1.20 protocol that encodes an inline `Holder<SoundEvent>`
    /// (including the `fixed_range` option byte) so subsequent fields align with the protocol.
    ///
    /// Returns `None` if the protocol registry lookup does not provide a valid packet id for `ClientboundSound`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let v = V1_20;
    /// let pos = SoundParams { x: 0.0, y: 64.0, z: 0.0, volume: 1.0, pitch: 1.0 };
    /// let pkt = v.note_sound(763, pos);
    /// assert!(pkt.is_some());
    /// ```
    fn note_sound(&self, proto: u32, pos: SoundParams) -> Option<EncodedPacket> {
        // 1.20+ Sound Effect is a `Holder<SoundEvent>`: `VarInt sound_id`
        // (0 = inline) + `Identifier name` + `option<f32> fixed_range`
        // (a leading bool) + category + pos + vol + pitch + seed. The
        // shared `ClientboundSound` encoder omits the `fixed_range`
        // option byte, which shifts every later field and over-runs
        // `seed` (`readerIndex(53)+length(8) exceeds writerIndex(56)`) —
        // the same bug fixed in the v1_19 bucket for 1.19.3+. Hand-encode
        // with the option byte present. minecraft-data `pc/1.20`
        // `ItemSoundHolder`/`ItemSoundEvent`.
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

    /// Creates a Boss Bar "Add" packet for the given UUID and title for the specified protocol.
    ///
    /// The packet sets health to 1.0, color to `VarInt(1)`, division to `VarInt(0)`, and flags to `0`.
    ///
    /// # Returns
    ///
    /// `Some(EncodedPacket)` containing a `ClientboundBossBar` Add action when the protocol can encode it, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use uuid::Uuid;
    /// let vb = V1_20;
    /// let id = Uuid::new_v4();
    /// let pkt = vb.bossbar_add(764, id, "Welcome");
    /// assert!(pkt.is_some());
    /// ```
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
        encode(proto, p::ClientboundKeepAlive { id })
    }

    /// Constructs a `minecraft:brand` plugin message packet containing the given brand string.
    ///
    /// Encodes the brand as a length-prefixed UTF-8 byte payload and produces an `EncodedPacket`
    /// for the `minecraft:brand` channel. Returns `None` if required encoding steps fail or the
    /// packet is not applicable for `proto`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let v = V1_20;
    /// let pkt = v.brand(766, "CodeRabbitProxy");
    /// assert!(pkt.is_some());
    /// ```
    fn brand(&self, proto: u32, brand: &str) -> Option<EncodedPacket> {
        let mut data = BytesMut::new();
        VarInt(brand.len() as i32).encode(&mut data).ok()?;
        data.put_slice(brand.as_bytes());
        encode(
            proto,
            p::ClientboundPluginMessage {
                channel: "minecraft:brand".to_owned(),
                data: data.to_vec(),
            },
        )
    }

    /// Builds the "set center chunk" limbo packet for supported 1.20 protocol versions.
    ///
    /// Returns `Some(EncodedPacket)` with the packet id selected for the given `proto` and a body containing two `VarInt(0)` values (chunk x and z). Returns `None` if `proto` is not one of the supported 1.20 versions (763, 764, 765, 766).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Returns a packet with id 0x4e for proto 763
    /// let pkt = V1_20.set_center_chunk(763).unwrap();
    /// assert_eq!(pkt.id, 0x4e);
    /// ```
    fn set_center_chunk(&self, proto: u32) -> Option<EncodedPacket> {
        // `[VarInt x][VarInt z]`. Ids per minecraft-data / ViaVersion
        // `ClientboundPackets1_20_*`.
        let id: u8 = match proto {
            763 => 0x4e, // 1.20 / 1.20.1
            764 => 0x50, // 1.20.2
            765 => 0x52, // 1.20.3 / 1.20.4
            766 => 0x54, // 1.20.5 / 1.20.6
            _ => return None,
        };
        let mut body = BytesMut::new();
        VarInt(0).encode(&mut body).ok()?;
        VarInt(0).encode(&mut body).ok()?;
        Some(EncodedPacket { id, body })
    }

    /// Constructs a void "level chunk with light" packet tailored to the specified protocol version.
    ///
    /// The function looks up the protocol-specific packet id for `ClientboundLevelChunkWithLight` and
    /// returns `None` if the id is unavailable. It selects the heightmap format based on `proto`:
    /// for protocol numbers <= 763 it uses named NBT heightmaps; for later protocols it uses anonymous
    /// (network) NBT. The chunk body is a void (empty) chunk with 24 sections (height 384) and the
    /// `trust_edges` flag disabled.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let v = crate::net::limbo_packets::v1_20::V1_20;
    /// // For a supported protocol this yields a packet
    /// let pkt = v.chunk_data(764);
    /// assert!(pkt.is_some() || pkt.is_none()); // presence depends on the local registry for the proto
    /// ```
    fn chunk_data(&self, proto: u32) -> Option<EncodedPacket> {
        let id = kojacoord_protocol::registry::cb_play(proto, "ClientboundLevelChunkWithLight");
        if id == 0xFF {
            return None;
        }
        // 1.20+ overworld is 384 high (24 sections) and DROPPED the
        // `trust_edges` bool. Heightmaps: named NBT at 1.20/1.20.1,
        // nameless (network) NBT from 1.20.2.
        let hm = if proto <= 763 {
            super::HeightmapFmt::NamedNbt
        } else {
            super::HeightmapFmt::AnonNbt
        };
        let body = super::void_chunk_body(24, false, hm);
        Some(EncodedPacket { id, body })
    }

    /// Constructs the "chunk batch start" limbo packet for applicable 1.20 protocol versions.
    ///
    /// Returns `Some(EncodedPacket)` with packet id `0x0d` and an empty body when `proto` is in `764..=766`; returns `None` for other protocol versions.
    ///
    /// # Parameters
    ///
    /// - `proto`: target protocol version.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let pkt = V1_20.chunk_batch_start(764);
    /// assert!(pkt.is_some());
    /// assert_eq!(pkt.unwrap().id, 0x0d);
    /// ```
    /// Set Default Spawn Position — required from 1.19.3 to dismiss the
    /// "Loading terrain" screen (1.20/1.20.1/1.20.2 fall in the window
    /// that has no GameEvent-13 yet). Ids per ViaVersion
    /// `ClientboundPackets1_19_4` (0x50, shared by 1.20/1.20.1) /
    /// `ClientboundPackets1_20_2` (0x52) / `ClientboundPackets1_20_3`
    /// (0x54) / `ClientboundPackets1_21` (0x56). Harmless on 765+, which
    /// also close via the chunk-wait GameEvent.
    fn set_default_spawn(&self, proto: u32) -> Option<EncodedPacket> {
        let id: u8 = match proto {
            763 => 0x50, // 1.20 / 1.20.1
            764 => 0x52, // 1.20.2
            765 => 0x54, // 1.20.3 / 1.20.4
            766 => 0x56, // 1.20.5 / 1.20.6
            _ => return None,
        };
        Some(EncodedPacket {
            id,
            body: super::default_spawn_body(),
        })
    }

    fn chunk_batch_start(&self, proto: u32) -> Option<EncodedPacket> {
        // 1.20.2+ only; empty body.
        let id: u8 = match proto {
            764..=766 => 0x0d,
            _ => return None,
        };
        Some(EncodedPacket {
            id,
            body: BytesMut::new(),
        })
    }

    /// Builds the "chunk batch finished" limbo packet for supported 1.20 protocol versions.
    ///
    /// Returns `Some(EncodedPacket)` containing packet id `0x0c` and a VarInt-encoded `batch_size` when `proto` is in `764..=766`; returns `None` for other protocol versions.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // produce a packet for protocol 764 with batch size 3
    /// let pkt = V1_20.chunk_batch_finished(764, 3).unwrap();
    /// assert_eq!(pkt.id, 0x0c);
    /// ```
    fn chunk_batch_finished(&self, proto: u32, batch_size: i32) -> Option<EncodedPacket> {
        let id: u8 = match proto {
            764..=766 => 0x0c,
            _ => return None,
        };
        let mut body = BytesMut::new();
        VarInt(batch_size).encode(&mut body).ok()?;
        Some(EncodedPacket { id, body })
    }

    /// Produce the "start waiting for level chunks" game event packet for supported 1.20.x protocol versions.
    ///
    /// The packet body is two fields: the event id `13` (u8) followed by the value `0.0` (f32).
    ///
    /// # Returns
    ///
    /// `Some(EncodedPacket)` containing the game event packet (event id `13` and value `0.0`) for supported protos, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let pkt = V1_20.start_wait_chunks_event(765).unwrap();
    /// assert_eq!(pkt.id, 0x20);
    /// assert_eq!(&pkt.body[..], &[13, 0, 0, 0, 0]); // u8 13 followed by f32 0.0
    /// ```
    fn start_wait_chunks_event(&self, proto: u32) -> Option<EncodedPacket> {
        // GameEvent 13 "start waiting for level chunks" — 1.20.3+ only.
        // Body = `[u8 event][f32 value]`.
        let id: u8 = match proto {
            765 => 0x20, // 1.20.3 / 1.20.4
            766 => 0x22, // 1.20.5 / 1.20.6
            _ => return None,
        };
        let mut body = BytesMut::new();
        body.put_u8(13);
        body.put_f32(0.0);
        Some(EncodedPacket { id, body })
    }
}
