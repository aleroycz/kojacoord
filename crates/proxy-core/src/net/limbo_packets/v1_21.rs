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
                sea_level: if proto >= 768 { Some(VarInt(0)) } else { None },
            },
        )
    }

    fn player_abilities(&self, proto: u32) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundPlayerAbilities {
                raw: vec![0x06, 0, 0, 0, 0, 0, 0, 0, 0],
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

    /// Builds a Clientbound system chat packet with the given JSON message.
    ///
    /// Returns an `EncodedPacket` containing the system chat (overlay flag set to false) for the specified protocol, or `None` if the packet cannot be constructed for that protocol.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let v = V1_21;
    /// let pkt = v.chat(768, r#"{"text":"hello"}"#);
    /// assert!(pkt.is_some());
    /// ```
    fn chat(&self, proto: u32, json_message: &str) -> Option<EncodedPacket> {
        encode(
            proto,
            p::ClientboundSystemChat {
                json_message: json_message.to_owned(),
                overlay: false,
            },
        )
    }

    /// Constructs a clientbound sound packet that plays the "minecraft:music_disc.cat" inline sound at a given position.
    ///
    /// The produced packet uses an inline sound event (sound id 0), encodes the fixed sound name "minecraft:music_disc.cat",
    /// omits the fixed-range value, sets the sound category to 2, encodes the position (x, y, z), volume, pitch, and a seed of 0.
    ///
    /// # Parameters
    ///
    /// - `proto`: protocol version to use when looking up the clientbound packet id; returns `None` if the packet id is not available for this protocol.
    /// - `pos`: sound parameters; the packet encodes `pos.x`, `pos.y`, `pos.z` (each scaled by 8 and written as i32), and `pos.volume` / `pos.pitch` as f32.
    ///
    /// # Returns
    ///
    /// `Some(EncodedPacket)` containing the encoded ClientboundSound packet for the given protocol and position, `None` if the packet id is unknown for `proto`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let v = V1_21;
    /// let pos = SoundParams { x: 0.0, y: 64.0, z: 0.0, volume: 1.0, pitch: 1.0 };
    /// let pkt = v.note_sound(770, pos);
    /// assert!(pkt.is_some());
    /// ```
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

    /// Create a Clientbound Boss Bar "Add" packet for the specified protocol.
    ///
    /// Constructs a boss bar packet that will add a bar with the provided `uuid` and `title`.
    /// The packet uses fixed defaults for health (1.0), color (1), division (0), and flags (0).
    ///
    /// # Returns
    ///
    /// `Some(EncodedPacket)` containing a BossBar `Add` action for the given protocol, or `None` if
    /// the packet cannot be encoded for that protocol.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use uuid::Uuid;
    ///
    /// // `V1_21` is a unit struct; call with a reference to produce the packet.
    /// let pkt = V1_21.bossbar_add(&V1_21, 770, Uuid::nil(), "Welcome");
    /// ```
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

    /// Constructs a "minecraft:brand" plugin message packet containing the given brand string.
    ///
    /// The packet payload encodes the brand length as a VarInt followed by the brand bytes. Returns
    /// `Some(EncodedPacket)` when encoding succeeds, or `None` if encoding fails for the target protocol.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Ensure `v` is an instance of V1_21 in scope.
    /// let pkt = V1_21.brand(770, "MyServerBrand");
    /// assert!(pkt.is_some());
    /// ```
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

    /// Returns an encoded "set center chunk" clientbound packet for the given protocol version.
    ///
    /// Chooses the raw packet id based on `proto` and constructs a packet body containing two `VarInt(0)` values.
    ///
    /// # Parameters
    ///
    /// - `proto`: protocol version used to select the packet id.
    ///
    /// # Returns
    ///
    /// `Some(EncodedPacket)` containing the selected packet id and body when the protocol is supported, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let v = V1_21;
    /// let pkt = v.set_center_chunk(768).unwrap();
    /// assert_eq!(pkt.id, 0x58);
    /// assert!(pkt.body.len() > 0);
    /// ```
    fn set_center_chunk(&self, proto: u32) -> Option<EncodedPacket> {
        // Ids per ViaVersion `ClientboundPackets1_21*` ordinals.
        let id: u8 = match proto {
            767 => 0x54,       // 1.21 / 1.21.1
            768..=769 => 0x58, // 1.21.2 / 1.21.3 / 1.21.4
            770..=772 => 0x57, // 1.21.5 / 1.21.6 / 1.21.7 / 1.21.8
            773..=774 => 0x5c, // 1.21.9 / 1.21.10 / 1.21.11
            _ => return None,
        };
        let mut body = BytesMut::new();
        VarInt(0).encode(&mut body).ok()?;
        VarInt(0).encode(&mut body).ok()?;
        Some(EncodedPacket { id, body })
    }

    /// Constructs an encoded "level chunk with light" packet containing an empty (void) chunk.
    ///
    /// Chooses the heightmap format based on the protocol: uses a nameless NBT heightmap for protocol
    /// versions less than 770 and a typed array heightmap for protocol 770 and above. Returns `None`
    /// if the clientbound packet id cannot be determined for the given protocol.
    ///
    /// # Parameters
    ///
    /// - `proto`: The target protocol version number; determines packet id lookup and heightmap format.
    ///
    /// # Returns
    ///
    /// `Some(EncodedPacket)` with the packet id and body for a 24-section void chunk when available,
    /// otherwise `None` if the packet id is unknown.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let ver = 770;
    /// let pkt = V1_21.chunk_data(&V1_21, ver);
    /// assert!(pkt.is_some());
    /// ```
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

    /// Constructs a "chunk batch start" encoded packet for the given protocol version.
    ///
    /// Returns `Some(EncodedPacket)` containing the protocol-specific packet id and an empty body when the protocol is supported, or `None` if unsupported.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let v = V1_21;
    /// let pkt = v.chunk_batch_start(770).unwrap();
    /// assert_eq!(pkt.id, 0x0c);
    /// assert!(pkt.body.is_empty());
    /// ```
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

    /// Builds a "chunk batch finished" limbo packet for the given protocol and batch size.
    ///
    /// The packet id is chosen based on `proto` (767..=769 => 0x0c, 770..=774 => 0x0b). The packet body contains `batch_size` encoded as a `VarInt`. Returns `None` when the protocol is not supported.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let v = V1_21;
    /// let pkt = v.chunk_batch_finished(770, 5).unwrap();
    /// assert_eq!(pkt.id, 0x0b);
    /// // body contains VarInt(5); exact bytes depend on VarInt encoding
    /// ```
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

    /// Builds the clientbound "start wait chunks" game event packet (GameEvent id 13 with value 0.0),
    /// choosing the correct packet id for the given protocol version.
    ///
    /// # Returns
    /// `Some(EncodedPacket)` containing the selected packet id and a body encoding `[u8 event][f32 value]`
    /// when `proto` is supported, or `None` if the protocol is unsupported.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let v = V1_21;
    /// let pkt = v.start_wait_chunks_event(767);
    /// assert!(pkt.is_some());
    /// ```
    fn start_wait_chunks_event(&self, proto: u32) -> Option<EncodedPacket> {
        // GameEvent 13 — `[u8 event][f32 value]`.
        let id: u8 = match proto {
            767 => 0x22,       // 1.21 / 1.21.1
            768..=769 => 0x23, // 1.21.2 / 1.21.3 / 1.21.4
            770..=772 => 0x22, // 1.21.5 / 1.21.6 / 1.21.7 / 1.21.8
            773..=774 => 0x26, // 1.21.9 / 1.21.10 / 1.21.11
            _ => return None,
        };
        let mut body = BytesMut::new();
        body.put_u8(13);
        body.put_f32(0.0);
        Some(EncodedPacket { id, body })
    }
}
