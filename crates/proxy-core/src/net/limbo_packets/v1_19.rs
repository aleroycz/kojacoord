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

    /// Builds a ClientboundPlayerPosition packet tailored to the specified protocol version.
    ///
    /// For protocol versions 755..=761 the encoded body includes a trailing `dismount_vehicle` boolean
    /// byte immediately after the `teleport_id`. For other supported protocol versions the encoded
    /// body uses the 1.19.4+ shape that omits the `dismount_vehicle` byte.
    ///
    /// # Examples
    ///
    /// ```
    /// let v = V1_19;
    /// let pos = PlayerPos { x: 0.0, y: 64.0, z: 0.0, yaw: 0.0, pitch: 0.0 };
    /// let pkt = v.player_position(761, pos, 1).unwrap();
    /// assert!(!pkt.body.is_empty());
    /// ```
    fn player_position(
        &self,
        proto: u32,
        pos: PlayerPos,
        teleport_id: i32,
    ) -> Option<EncodedPacket> {
        // 1.17 / 1.17.1 / 1.18 / 1.18.2 / 1.19 / 1.19.1 / 1.19.2 /
        // 1.19.3 (proto 755 - 761) carry a trailing
        // `dismount_vehicle: bool` byte after `teleport_id`. Mojang
        // added it at 1.17 (per ViaVersion `EntityPacketRewriter1_17`:
        // `create(Types.BOOLEAN, false); // Dismount vehicle`) and
        // removed it at 1.19.4 (proto 762) — ViaVersion's 1.19.3→1.19.4
        // `EntityPacketRewriter1_19_4` line 93 READS the boolean from
        // the 1.19.3 packet and drops it. minecraft-data confirms:
        // `pc/1.19.2` packet_position ends in `dismountVehicle`,
        // `pc/1.19.4` does not.
        //
        // 762+ falls through to the typed encoder below, which emits the
        // dismount-less 1.19.4 shape. Including 762 here sent one byte
        // too many — the user-reported "ClientboundPlayerPosition was
        // larger than I expected, found 1 byte extra".
        if (755..=761).contains(&proto) {
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

    /// Encodes a clientbound music-disc sound packet shaped for the specified protocol version.
    ///
    /// Builds the wire-format for the `minecraft:music_disc.cat` sound event using the packet shape
    /// expected by the given `proto`. Behavior by proto range:
    /// - 755–758: legacy NamedSoundEffect shape (Identifier name, VarInt category, scaled i32 positions,
    ///   f32 volume, f32 pitch).
    /// - 759–760: prefix-less 1.19/1.19.1/1.19.2 custom-sound shape (name length + name, VarInt category,
    ///   scaled i32 positions, f32 volume, f32 pitch, i64 seed).
    /// - 761+: Holder<SoundEvent> inline form (VarInt 0, name length + name, a `fixed_range` option byte,
    ///   VarInt category, scaled i32 positions, f32 volume, f32 pitch, i64 seed).
    ///
    /// Returns `Some(EncodedPacket)` containing the correctly encoded packet body and packet id for the
    /// target proto, or `None` if the packet id is unsupported for that proto or required encodings fail.
    ///
    /// # Examples
    ///
    /// ```
    /// use uuid::Uuid;
    /// // Construct params with the same public fields used by the codebase.
    /// let params = crate::net::limbo_packets::SoundParams { x: 0.0, y: 64.0, z: 0.0, volume: 1.0, pitch: 1.0 };
    /// let v = crate::net::limbo_packets::v1_19::V1_19;
    /// let pkt = v.note_sound(759, params);
    /// assert!(pkt.is_some());
    /// ```
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
        // proto 759 - 760 (1.19 / 1.19.1 / 1.19.2): string-named sound
        // (`ClientboundCustomSoundEffect`) — `[Identifier name][VarInt
        // category][i32 x*8][i32 y*8][i32 z*8][f32 vol][f32 pitch][i64
        // seed]`. The `seed` trailer exists from 1.19.0, but the
        // `sound_type` VarInt holder prefix is 1.19.3+ ONLY. ViaVersion
        // confirms this: `Protocol1_19_1To1_19_3` rewrites the old
        // string-based `CUSTOM_SOUND` into `Types.SOUND_EVENT` (the
        // holder) only at 1.19.3, so 759/760 carry no prefix.
        //
        // The v1_21_x `ClientboundSound` encoder below writes the
        // 1.19.3+ shape with a leading `sound_type` VarInt(0). Sending
        // that to a 1.19/1.19.2 client makes it read our `sound_type`
        // byte as the `sound_name` string length, shifting every
        // subsequent field — the misaligned string length surfaces as
        // the client-side `IndexOutOfBoundsException` on a corrupt
        // VarInt. Hand-encode the correct prefix-less shape here.
        if (759..=760).contains(&proto) {
            let pid =
                kojacoord_protocol::versions::v1_21_x::play::ClientboundSound::packet_id(proto);
            if pid == 0xFF {
                return None;
            }
            let mut body = BytesMut::new();
            let name = b"minecraft:music_disc.cat";
            VarInt(name.len() as i32).encode(&mut body).ok()?;
            body.put_slice(name);
            VarInt(2).encode(&mut body).ok()?; // sound_category
            body.put_i32((pos.x * 8.0) as i32);
            body.put_i32((pos.y * 8.0) as i32);
            body.put_i32((pos.z * 8.0) as i32);
            body.put_f32(pos.volume);
            body.put_f32(pos.pitch);
            body.put_i64(0); // seed
            return Some(EncodedPacket { id: pid, body });
        }
        // proto 761+ (1.19.3 / 1.19.4): the sound field is a
        // `Holder<SoundEvent>` — `[VarInt sound_id]` where 0 means an
        // INLINE sound event: `[Identifier name][option<f32> fixed_range]`
        // (the option is a leading `bool`, false here). minecraft-data
        // `pc/1.19.4` `ItemSoundHolder`/`ItemSoundEvent` confirm the
        // `fixed_range` option. The shared `v1_21_x::ClientboundSound`
        // encoder omits that bool, so the client read every following
        // field shifted by one byte and over-ran `seed` at the end
        // (`readerIndex(53)+length(8) exceeds writerIndex(56)`). Hand-
        // encode the holder with the option byte present.
        let pid = kojacoord_protocol::versions::v1_21_x::play::ClientboundSound::packet_id(proto);
        if pid == 0xFF {
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
        Some(EncodedPacket { id: pid, body })
    }

    /// Add a boss bar for the given UUID with the provided title.
    ///
    /// The resulting packet uses the BossBar `Add` action (health = 1.0, color = 1, division = 0, flags = 0).
    ///
    /// # Parameters
    ///
    /// - `proto`: protocol version used to select the packet id and wire format; may cause `None` if unsupported.
    ///
    /// # Returns
    ///
    /// `Some(EncodedPacket)` containing a BossBar `Add` action for the given UUID and title, or `None` if the packet id/wire shape is unsupported for `proto`.
    ///
    /// # Examples
    ///
    /// ```
    /// let v = V1_19;
    /// let id = uuid::Uuid::new_v4();
    /// let pkt = v.bossbar_add(762, id, "Hello world");
    /// assert!(pkt.is_some());
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
        encode(proto, p::ClientboundKeepAlive { id })
    }

    /// Constructs a `minecraft:brand` plugin-message packet containing the given brand string.
    ///
    /// The payload is the brand length encoded as a VarInt followed by the raw brand bytes.
    /// Returns `Some(EncodedPacket)` containing the plugin message for the specified protocol, or `None` if encoding fails for that protocol.
    ///
    /// # Examples
    ///
    /// ```
    /// let v = V1_19;
    /// let pkt = v.brand(762, "my-proxy").expect("should encode");
    /// // `pkt` is an EncodedPacket ready to be sent to a client
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

    /// Constructs the per-protocol "SetChunkCacheCenter" / Update View Position packet with chunk coordinates set to (0, 0).
    ///
    /// The chosen packet id depends on `proto`:
    /// - 755..=758 → 0x49
    /// - 759 → 0x48
    /// - 760 → 0x4b
    /// - 761 → 0x4a
    /// - 762 → 0x4e
    ///   Returns `None` for unsupported protocol versions. The packet body contains two VarInts (chunk x and chunk z), both zero.
    ///
    /// # Examples
    ///
    /// ```
    /// let v = V1_19;
    /// let pkt = v.set_center_chunk(759).unwrap();
    /// assert_eq!(pkt.id, 0x48);
    /// ```
    fn set_center_chunk(&self, proto: u32) -> Option<EncodedPacket> {
        // `SetChunkCacheCenter` / Update View Position = `[VarInt x][VarInt z]`.
        // Not in the central registry, so the per-proto id is pinned here
        // (minecraft-data `protocol.json` + ViaVersion
        // `ClientboundPackets1_19_3`). Must precede the void chunk or the
        // client discards it and stays on "Loading terrain".
        let id: u8 = match proto {
            755..=758 => 0x49, // 1.17 / 1.17.1 / 1.18 / 1.18.2
            759 => 0x48,       // 1.19
            760 => 0x4b,       // 1.19.1 / 1.19.2
            761 => 0x4a,       // 1.19.3
            762 => 0x4e,       // 1.19.4
            _ => return None,
        };
        let mut body = BytesMut::new();
        VarInt(0).encode(&mut body).ok()?; // chunk x
        VarInt(0).encode(&mut body).ok()?; // chunk z
        Some(EncodedPacket { id, body })
    }

    /// Builds a "void" ClientboundLevelChunkWithLight packet body for the given protocol version.
    ///
    /// Chooses the section count based on the protocol: 16 sections when `proto <= 756`, 24 sections otherwise,
    /// and uses the named-NBT heightmap / trust_edges era layout. Returns `None` if the protocol registry does not
    /// define an id for `ClientboundLevelChunkWithLight`.
    ///
    /// # Examples
    ///
    /// ```
    /// let v = V1_19;
    /// assert!(v.chunk_data(759).is_some());
    /// ```
    fn chunk_data(&self, proto: u32) -> Option<EncodedPacket> {
        // `ClientboundLevelChunkWithLight` (1.18 combined chunk+light).
        // 755-762 are the named-NBT-heightmap, `trust_edges`-present era.
        // Section count = world_height / 16: 1.17 overworld is 256 high
        // (16 sections); 1.18+ raised it to 384 (24). Built by the shared
        // `void_chunk_body` so the light-mask handling stays consistent
        // with the v1_20/v1_21 buckets.
        let pid = kojacoord_protocol::registry::cb_play(proto, "ClientboundLevelChunkWithLight");
        if pid == 0xFF {
            return None;
        }
        // 1.17 / 1.17.1 (proto 755/756) predate the 1.18 combined chunk+light
        // packet. They use the distinct 1.17 `LevelChunk` shape (section
        // bitmask + chunk-level biomes + 1.16-format sections, no light), with
        // light delivered separately via `light_update`. Sending the 1.18
        // combined body to a 1.17 client makes it read the heightmap's TAG byte
        // as the (missing) section-bitmask length and fail with
        // "Can't read heightmap in packet for [0, 0]".
        if proto <= 756 {
            let body = super::void_chunk_body_1_17(16); // 1.17 overworld = 16 sections (256 high)
            return Some(EncodedPacket { id: pid, body });
        }
        let sections = 24; // 1.18+ overworld = 384 high
        let body = super::void_chunk_body(sections, true, super::HeightmapFmt::NamedNbt);
        Some(EncodedPacket { id: pid, body })
    }

    fn light_update(&self, proto: u32) -> Option<EncodedPacket> {
        // Standalone LightUpdate only for 1.17 / 1.17.1 (proto 755/756); 1.18+
        // folds light into the combined chunk packet. Id 0x25 per ViaVersion
        // `ClientboundPackets1_17::LIGHT_UPDATE`.
        if !(755..=756).contains(&proto) {
            return None;
        }
        let body = super::light_update_body_1_17(16);
        Some(EncodedPacket { id: 0x25, body })
    }
}

/// Hand-encodes a JoinGame (ClientboundLogin) packet for Minecraft 1.17–1.18 protos.
///
/// Builds the exact wire-format used by 1.17/1.18 clients, including:
/// - entity id, hardcore flag, game mode and previous game mode
/// - a dimensions list containing `world_name`
/// - the registry codec (NBT-framed) and the inline dimension NBT for `minecraft:overworld`
/// - the repeated world name string, hashed seed, player limits, view/simulation distances,
///   and the protocol-specific trailing booleans.
///
/// Returns `None` if the packet id for `ClientboundLogin` is unavailable for `proto`
/// or if necessary codec/NBT builders fail.
///
/// # Examples
///
/// ```
/// let pkt = build_join_game_1_17_or_1_18(757, "minecraft:overworld");
/// assert!(pkt.is_some());
/// ```
fn build_join_game_1_17_or_1_18(proto: u32, world_name: &str) -> Option<EncodedPacket> {
    let pid = p::ClientboundLogin::packet_id(proto);
    if pid == 0xFF {
        return None;
    }
    let registry_codec = crate::protocol::build_dimension_codec_for_proto(proto).ok()?;
    // Inline dimension MUST match the registry's overworld element
    // byte-for-byte (same #infiniburn / min_y / height) or the 1.18.x
    // client's strict DimensionType codec rejects it.
    let dimension_nbt = crate::protocol::dimension_codec::inline_dimension_nbt_for_proto(
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

/// Build a hand-encoded Clientbound Respawn packet matching the 1.17/1.18 wire shape.
///
/// Encodes the respawn packet fields in the order required by protocols in the 1.17–1.18 range:
/// an inline dimension NBT for the overworld, the world name string, hashed seed, game mode,
/// previous game mode, and the three trailing boolean bytes (is_debug, is_flat, copy_metadata).
///
/// Returns `Some(EncodedPacket)` containing the encoded ClientboundRespawn for the given `proto` and
/// `world_name`, or `None` if the packet id for `proto` is unavailable or constructing the
/// inline dimension NBT fails.
///
/// # Examples
///
/// ```
/// // Ensure a packet can be constructed for a 1.17-era protocol.
/// let pkt = build_respawn_1_17_or_1_18(755, "minecraft:overworld");
/// assert!(pkt.is_some());
/// ```
fn build_respawn_1_17_or_1_18(proto: u32, world_name: &str) -> Option<EncodedPacket> {
    let pid = p::ClientboundRespawn::packet_id(proto);
    if pid == 0xFF {
        return None;
    }
    let dimension_nbt = crate::protocol::dimension_codec::inline_dimension_nbt_for_proto(
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
    fn proto_761_player_position_body_is_35_bytes_with_dismount() {
        // 1.19.3 — LAST proto with dismount_vehicle.
        assert_eq!(body_len(761), 35);
    }

    #[test]
    fn proto_762_player_position_body_is_34_bytes_no_dismount() {
        // 1.19.4 — Mojang removed dismount_vehicle here (proto 762), not
        // 763. Including 762 in the dismount window sent 1 byte extra and
        // crashed the 1.19.4 client's PlayerPosition decoder.
        assert_eq!(body_len(762), 34);
    }

    #[test]
    fn proto_763_player_position_body_is_34_bytes_no_dismount() {
        // 1.20 — also dismount-less.
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

    /// The void chunk must parse cleanly per the 1.18/1.19
    /// `LevelChunkWithLight` wire shape with no leftover bytes, and carry
    /// the height-correct section count (16 for 1.17, 24 for 1.18+).
    #[test]
    fn void_chunk_parses_with_correct_section_count() {
        use bytes::Buf;
        use kojacoord_protocol::codec::Decode;
        use kojacoord_protocol::types::nbt::Nbt;

        for (proto, want_sections) in [(758u32, 24), (759, 24), (760, 24), (761, 24), (762, 24)] {
            // Every 1.18+ proto must also have a Set Center Chunk packet
            // or the client discards the chunk and hangs on loading.
            assert!(
                V1_19.set_center_chunk(proto).is_some(),
                "proto {proto} missing set_center_chunk"
            );
            let pkt = V1_19.chunk_data(proto).expect("chunk built");
            let mut b = bytes::Bytes::copy_from_slice(&pkt.body);
            assert_eq!(b.get_i32(), 0, "chunk x");
            assert_eq!(b.get_i32(), 0, "chunk z");
            Nbt::decode(&mut b).expect("heightmaps NBT");
            let cd_len = VarInt::decode(&mut b).unwrap().0 as usize;
            // each empty section = 2 (i16) + 3 (block states) + 3 (biomes)
            assert_eq!(cd_len, want_sections * 8, "proto {proto} chunkData size");
            b.advance(cd_len);
            assert_eq!(VarInt::decode(&mut b).unwrap().0, 0, "block entities");
            assert_eq!(b.get_u8(), 1, "trust edges");
            assert_eq!(VarInt::decode(&mut b).unwrap().0, 0, "skyLightMask");
            assert_eq!(VarInt::decode(&mut b).unwrap().0, 0, "blockLightMask");
            let expected = ((1u64 << (want_sections + 2)) - 1) as i64;
            assert_eq!(
                VarInt::decode(&mut b).unwrap().0,
                1,
                "emptySkyLightMask len"
            );
            assert_eq!(
                b.get_i64(),
                expected,
                "emptySkyLightMask covers all sections"
            );
            assert_eq!(
                VarInt::decode(&mut b).unwrap().0,
                1,
                "emptyBlockLightMask len"
            );
            assert_eq!(b.get_i64(), expected);
            assert_eq!(VarInt::decode(&mut b).unwrap().0, 0, "sky light arrays");
            assert_eq!(VarInt::decode(&mut b).unwrap().0, 0, "block light arrays");
            assert_eq!(b.remaining(), 0, "proto {proto} chunk has trailing bytes");
        }
    }

    /// 1.17 / 1.17.1 (proto 755/756) must use the pre-1.18 `LevelChunk`
    /// shape — section bitmask, chunk-level biomes, 1.16-format sections — and
    /// fully consume. The missing bitmask was the "Can't read heightmap in
    /// packet for [0, 0]" bug. Field order mirrors ViaVersion `ChunkType1_17`.
    #[test]
    fn proto_755_756_chunk_is_1_17_shape_and_parses() {
        use bytes::Buf;
        use kojacoord_protocol::codec::Decode;
        use kojacoord_protocol::types::nbt::Nbt;

        for proto in [755u32, 756] {
            let pkt = V1_19.chunk_data(proto).expect("chunk built");
            assert_eq!(pkt.id, 0x22, "1.17 LEVEL_CHUNK id");
            let mut b = bytes::Bytes::copy_from_slice(&pkt.body);

            assert_eq!(b.get_i32(), 0, "chunk x");
            assert_eq!(b.get_i32(), 0, "chunk z");

            // Section bitmask: long array, all 16 sections present.
            assert_eq!(VarInt::decode(&mut b).unwrap().0, 1, "bitmask long count");
            assert_eq!(b.get_i64(), 0xFFFF, "16 sections present");

            // Heightmaps NBT (must decode straight after the bitmask).
            Nbt::decode(&mut b).expect("heightmaps NBT");

            // Chunk-level biomes: 16 sections × 64 = 1024 cells, all id 0.
            assert_eq!(VarInt::decode(&mut b).unwrap().0, 1024, "biome cell count");
            for _ in 0..1024 {
                assert_eq!(VarInt::decode(&mut b).unwrap().0, 0, "biome id 0");
            }

            // Section data: 16 sections × (short + byte + VarInt(1) + VarInt(0)
            // + VarInt(256) + 256×i64) = 16 × (2+1+1+1+2+2048) = 16 × 2055.
            let cd_len = VarInt::decode(&mut b).unwrap().0 as usize;
            assert_eq!(cd_len, 16 * 2055, "proto {proto} section data size");
            b.advance(cd_len);

            assert_eq!(VarInt::decode(&mut b).unwrap().0, 0, "block entities");
            assert_eq!(b.remaining(), 0, "proto {proto} chunk has trailing bytes");

            // Light is a separate packet for 1.17.
            let light = V1_19.light_update(proto).expect("1.17 light packet");
            assert_eq!(light.id, 0x25, "1.17 LIGHT_UPDATE id");
            let mut l = bytes::Bytes::copy_from_slice(&light.body);
            assert_eq!(VarInt::decode(&mut l).unwrap().0, 0, "light x");
            assert_eq!(VarInt::decode(&mut l).unwrap().0, 0, "light z");
            assert_eq!(l.get_u8(), 1, "trust edges");
            assert_eq!(VarInt::decode(&mut l).unwrap().0, 0, "skyLightMask");
            assert_eq!(VarInt::decode(&mut l).unwrap().0, 0, "blockLightMask");
            assert_eq!(
                VarInt::decode(&mut l).unwrap().0,
                1,
                "emptySkyLightMask len"
            );
            assert_eq!(l.get_i64(), 0x3FFFF, "18 light sections empty");
            assert_eq!(
                VarInt::decode(&mut l).unwrap().0,
                1,
                "emptyBlockLightMask len"
            );
            assert_eq!(l.get_i64(), 0x3FFFF);
            assert_eq!(VarInt::decode(&mut l).unwrap().0, 0, "sky light arrays");
            assert_eq!(VarInt::decode(&mut l).unwrap().0, 0, "block light arrays");
            assert_eq!(l.remaining(), 0, "proto {proto} light has trailing bytes");
        }

        // 1.18+ keeps light folded into the chunk — no standalone packet.
        assert!(
            V1_19.light_update(758).is_none(),
            "1.18 has no separate light"
        );
    }

    /// 1.19 / 1.19.2 sound = `[VarInt(24) name][VarInt cat][i32×3]`
    /// `[f32×2][i64 seed]` = 1 + 24 + 1 + 12 + 8 + 8 = 54. Crucially it
    /// MUST start with the name's length VarInt (24), NOT a `sound_type`
    /// VarInt(0) holder prefix — that prefix is 1.19.3+ only and sending
    /// it desyncs the 1.19/1.19.2 client (IndexOutOfBounds on the
    /// shifted string length).
    #[test]
    fn proto_759_760_sound_is_prefixless_with_seed() {
        for proto in [759u32, 760] {
            let pkt = V1_19
                .note_sound(
                    proto,
                    SoundParams {
                        x: 0.0,
                        y: 256.0,
                        z: 0.0,
                        volume: 1.0,
                        pitch: 1.0,
                    },
                )
                .expect("must build");
            assert_eq!(
                pkt.body.len(),
                54,
                "proto {proto} sound body must be 54 bytes (no sound_type prefix, has seed)"
            );
            assert_eq!(
                pkt.body[0], 24,
                "proto {proto} sound must start with name length VarInt(24), not a sound_type prefix"
            );
        }
    }

    /// 1.19.3+ (761/762) sends a `Holder<SoundEvent>`: VarInt(0) inline
    /// marker, name, then the `fixed_range` option byte, then category /
    /// pos / vol / pitch / seed. Body = 1 + (1+24) + 1 + 1 + 12 + 8 + 8 =
    /// 56. The `fixed_range` byte was the missing one that caused the
    /// `readerIndex(53)+length(8)` seed over-read.
    #[test]
    fn proto_761_762_sound_holder_has_fixed_range_option() {
        use bytes::Buf;
        use kojacoord_protocol::codec::Decode;
        for proto in [761u32, 762] {
            let pkt = V1_19
                .note_sound(
                    proto,
                    SoundParams {
                        x: 0.0,
                        y: 256.0,
                        z: 0.0,
                        volume: 1.0,
                        pitch: 1.0,
                    },
                )
                .expect("must build");
            assert_eq!(pkt.body.len(), 56, "proto {proto} holder sound body");
            let mut b = bytes::Bytes::copy_from_slice(&pkt.body);
            assert_eq!(VarInt::decode(&mut b).unwrap().0, 0, "inline sound_id 0");
            let n = VarInt::decode(&mut b).unwrap().0 as usize;
            b.advance(n); // sound name
            assert_eq!(b.get_u8(), 0, "fixed_range option absent");
            assert_eq!(VarInt::decode(&mut b).unwrap().0, 2, "sound_category");
            b.advance(12 + 8); // pos + vol/pitch
            assert_eq!(b.get_i64(), 0, "seed fits exactly");
            assert_eq!(b.remaining(), 0, "no trailing bytes");
        }
    }

    /// Parse the proto-759 JoinGame body exactly as a vanilla 1.19
    /// client would and assert every byte is consumed — a leftover or
    /// over-read is a framing desync that crashes the client decoder.
    #[test]
    fn proto_759_join_game_fully_parses() {
        use bytes::Buf;
        use kojacoord_protocol::codec::Decode;
        use kojacoord_protocol::types::nbt::Nbt;

        let pkt = V1_19
            .join_game(759, "minecraft:overworld")
            .expect("must build");
        let mut src = bytes::Bytes::copy_from_slice(&pkt.body);

        let _entity_id = src.get_i32();
        let _is_hardcore = src.get_u8();
        let _game_mode = src.get_u8();
        let _prev = src.get_i8();
        let dim_count = VarInt::decode(&mut src).unwrap().0;
        for _ in 0..dim_count {
            let _ = String::decode(&mut src).unwrap();
        }
        // registry_codec NBT — must self-frame to exactly its own bytes.
        let _nbt = Nbt::decode(&mut src).expect("registry codec must decode");
        let _dim_type = String::decode(&mut src).expect("dimension_type");
        let _dim_name = String::decode(&mut src).expect("dimension_name");
        let _seed = src.get_i64();
        let _max = VarInt::decode(&mut src).unwrap();
        let _view = VarInt::decode(&mut src).unwrap();
        let _sim = VarInt::decode(&mut src).unwrap();
        let _rdi = src.get_u8();
        let _ers = src.get_u8();
        let _dbg = src.get_u8();
        let _flat = src.get_u8();
        let _has_death = src.get_u8();
        assert_eq!(
            src.remaining(),
            0,
            "JoinGame body not fully consumed — {} bytes left (client desyncs here)",
            src.remaining()
        );
    }
}
