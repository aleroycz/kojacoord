//! Per-canonical-version packet builders for limbo.
//!
//! Each `LimboPackets` impl knows how to build one canonical-version
//! family's wire-shape for every packet limbo emits (JoinGame, Respawn,
//! Position, KeepAlive, Chat, Sound, BossBar, etc.) — returning an
//! [`EncodedPacket`] = `(packet_id, body)`. The `LimboHandler` keeps a
//! `&'static dyn LimboPackets` pointer chosen at construction time;
//! every `send_*` method becomes a one-liner that asks the impl for
//! the encoded bytes and writes them.
//!
//! Adding a new canonical version is one new module file plus one
//! entry in [`for_version`] — no edits to `limbo.rs`.
//!
//! `None` returned from a builder means "this version doesn't speak
//! that packet" (e.g. pre-netty has no BossBar). The handler skips it.

use bytes::{BufMut, BytesMut};
use kojacoord_protocol::CanonicalVersion;
use uuid::Uuid;

/// Convert a JSON chat component (e.g. `{"text":"…","color":"yellow"}`) to a
/// **nameless** network-NBT text component — the wire form 1.20.3+ (proto
/// 765+) expects for chat components. 1.20.3 switched text components from
/// JSON strings to NBT (ViaVersion rewrites them via
/// `ComponentUtil.jsonToTag`); sending the old JSON string makes the client
/// fail to decode the component (e.g. `Failed to decode packet
/// 'clientbound/minecraft:system_chat'`). Returns `None` if the JSON can't be
/// represented (the caller then falls back rather than emit a broken packet).
pub(crate) fn json_component_to_nameless_nbt(json: &str) -> Option<Vec<u8>> {
    use kojacoord_protocol::codec::Encode;
    use kojacoord_protocol::types::nbt::{Nbt, NbtTag};

    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let root = match json_value_to_nbt(&value)? {
        NbtTag::Compound(map) => map,
        _ => return None,
    };
    let nbt = Nbt {
        name: String::new(),
        root,
    };
    let mut buf = BytesMut::new();
    nbt.encode(&mut buf).ok()?;
    // `Nbt::encode` emits `0x0a <u16 name_len=0> <payload>`. Strip the
    // 2-byte empty name to get the nameless network form `0x0a <payload>`.
    let bytes = buf.as_ref();
    if bytes.len() < 3 || bytes[0] != 0x0a {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() - 2);
    out.push(0x0a);
    out.extend_from_slice(&bytes[3..]);
    Some(out)
}

/// Map a `serde_json::Value` onto an `NbtTag`. Covers the subset chat
/// components use: objects, arrays, strings, bools, and numbers.
fn json_value_to_nbt(value: &serde_json::Value) -> Option<kojacoord_protocol::types::nbt::NbtTag> {
    use kojacoord_protocol::types::nbt::NbtTag;
    use serde_json::Value;
    use std::collections::HashMap;
    Some(match value {
        Value::String(s) => NbtTag::String(s.clone()),
        Value::Bool(b) => NbtTag::Byte(*b as i8),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                NbtTag::Int(i as i32)
            } else {
                NbtTag::Double(n.as_f64()?)
            }
        },
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(json_value_to_nbt(it)?);
            }
            NbtTag::List(out)
        },
        Value::Object(map) => {
            let mut out = HashMap::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), json_value_to_nbt(v)?);
            }
            NbtTag::Compound(out)
        },
        Value::Null => return None,
    })
}

/// Heightmaps wire encoding for `LevelChunkWithLight`, which changed
/// twice in the modern era:
///   * [`NamedNbt`]  — ≤ 1.20.1 (proto ≤ 763): a *named* NBT compound.
///   * [`AnonNbt`]   — 1.20.2 – 1.21.4 (764-769): a *nameless* network
///     NBT compound.
///   * [`Array`]     — 1.21.5+ (770+): a length-prefixed array of
///     `{VarInt type, LongArray data}` (per ViaVersion
///     `BlockItemPacketRewriter1_21_5`; an empty array is valid).
#[derive(Clone, Copy)]
pub(crate) enum HeightmapFmt {
    NamedNbt,
    AnonNbt,
    Array,
}

/// Builds a single void (all-air) `LevelChunkWithLight` body for chunk (0,0).
///
/// The returned buffer encodes an all-air chunk with `sections` vertical sections
/// (height / 16), optional legacy `trust_edges` byte (present in protocols ≤ 762),
/// and a heightmap encoded according to `hm`. Sections use single-valued palettes
/// (air block state 0, biome id 0). Light masks are set to indicate every light
/// section is present but contains zeroed data so clients treat the chunk as fully lit.
///
/// # Examples
///
/// ```ignore
/// // Construct a 24-section void chunk using named NBT heightmaps and legacy trust_edges.
/// let body = limbo_packets::void_chunk_body(24, true, limbo_packets::HeightmapFmt::NamedNbt);
/// assert!(!body.is_empty());
/// ```
pub(crate) fn void_chunk_body(sections: usize, trust_edges: bool, hm: HeightmapFmt) -> BytesMut {
    use kojacoord_protocol::codec::Encode;
    use kojacoord_protocol::types::VarInt;

    let mut body = BytesMut::new();
    body.put_i32(0); // chunk x
    body.put_i32(0); // chunk z

    // Heightmaps. The NBT eras carry a MOTION_BLOCKING long array (256
    // entries @ 9 bits = 37 longs, all zero) — matching the proven
    // 1.18-1.19.4 limbo path. The 1.21.5+ array era accepts an empty
    // array (ViaVersion `EMPTY_HEIGHTMAPS`).
    match hm {
        HeightmapFmt::NamedNbt => {
            body.put_u8(0x0a); // TAG_Compound
            body.put_u16(0); // empty name
            put_motion_blocking_field(&mut body);
            body.put_u8(0x00); // TAG_End
        },
        HeightmapFmt::AnonNbt => {
            body.put_u8(0x0a); // TAG_Compound, no name (network NBT)
            put_motion_blocking_field(&mut body);
            body.put_u8(0x00); // TAG_End
        },
        HeightmapFmt::Array => {
            let _ = VarInt(0).encode(&mut body); // empty heightmap array
        },
    }

    // chunkData: `sections` empty sections.
    let mut cd = BytesMut::new();
    for _ in 0..sections {
        cd.put_i16(0); // non-air block count
        cd.put_u8(0); // block states: bits per entry = 0 (single value)
        let _ = VarInt(0).encode(&mut cd); // palette: minecraft:air
        let _ = VarInt(0).encode(&mut cd); // data array length
        cd.put_u8(0); // biomes: bits per entry = 0
        let _ = VarInt(0).encode(&mut cd); // palette: biome registry id 0
        let _ = VarInt(0).encode(&mut cd); // data array length
    }
    let _ = VarInt(cd.len() as i32).encode(&mut body);
    body.put_slice(&cd);

    let _ = VarInt(0).encode(&mut body); // block entities count
    if trust_edges {
        body.put_u8(1); // ≤1.19.4 only
    }

    // Light: declare EVERY light section explicitly empty rather than
    // leaving all masks blank. A chunk has `sections + 2` light sections
    // (one below, one above the buildable range). With all-blank masks
    // the client's light engine has no information and never marks the
    // chunk fully lit, so the "Loading terrain" screen never clears even
    // though the chunk geometry loaded. Setting emptySky/emptyBlock to
    // cover all light sections (and leaving the data masks empty) tells
    // it "all sections are lit with zero light" → chunk becomes ready.
    let light_sections = sections + 2;
    let empty_mask: i64 = if light_sections >= 64 {
        -1
    } else {
        ((1u64 << light_sections) - 1) as i64
    };
    let _ = VarInt(0).encode(&mut body); // skyLightMask (no data sections)
    let _ = VarInt(0).encode(&mut body); // blockLightMask (no data sections)
    let _ = VarInt(1).encode(&mut body); // emptySkyLightMask: 1 long
    body.put_i64(empty_mask);
    let _ = VarInt(1).encode(&mut body); // emptyBlockLightMask: 1 long
    body.put_i64(empty_mask);
    let _ = VarInt(0).encode(&mut body); // sky light array count
    let _ = VarInt(0).encode(&mut body); // block light array count
    body
}

/// Builds a void (all-air) 1.17 / 1.17.1 `LevelChunk` packet body (proto 755/756).
///
/// 1.17 predates the 1.18 combined chunk+light packet, so this uses the
/// distinct 1.17 wire shape (per ViaVersion `ChunkType1_17` /
/// `ChunkSectionType1_16`):
///   * a `BitSet` section mask (long array) BEFORE the heightmaps — the field
///     the 1.18 combined format dropped. Omitting it makes the client read the
///     heightmap's `0x0a` TAG byte as the mask length and then fail with
///     "Can't read heightmap in packet for [0, 0]".
///   * chunk-level biomes (`VAR_INT_ARRAY`, 64 cells per section, all id 0) —
///     1.18 moved biomes into the sections instead.
///   * sections in the **1.16** palette format: a *minimum of 4 bits per
///     block* (1.16/1.17 has no single-valued bits=0 palette), a one-entry air
///     palette, and a full 256-long data array of zeros.
///   * NO light / `trust_edges` — light is the separate `LightUpdate` packet
///     ([`light_update_body_1_17`]).
pub(crate) fn void_chunk_body_1_17(sections: usize) -> BytesMut {
    use kojacoord_protocol::codec::Encode;
    use kojacoord_protocol::types::VarInt;

    let mut body = BytesMut::new();
    body.put_i32(0); // chunk x
    body.put_i32(0); // chunk z

    // Section bitmask: BitSet.toLongArray() with every section present.
    let mask: i64 = if sections >= 64 {
        -1
    } else {
        ((1u64 << sections) - 1) as i64
    };
    let _ = VarInt(1).encode(&mut body); // long-array length
    body.put_i64(mask);

    // Heightmaps (named NBT). 256-high overworld → 9 bits/256 entries → 37 longs.
    body.put_u8(0x0a); // TAG_Compound
    body.put_u16(0); // empty name
    put_motion_blocking_field(&mut body);
    body.put_u8(0x00); // TAG_End

    // Chunk-level biomes: VAR_INT_ARRAY = VarInt(len) + len×VarInt. The cell
    // count is 16 horizontal (4×4) × (height/4) vertical = 64 per section.
    let biome_cells = sections * 64;
    let _ = VarInt(biome_cells as i32).encode(&mut body);
    for _ in 0..biome_cells {
        let _ = VarInt(0).encode(&mut body); // biome id 0
    }

    // Sections, 1.16 format (no per-section biomes).
    let mut cd = BytesMut::new();
    for _ in 0..sections {
        cd.put_i16(0); // non-air block count
        cd.put_u8(4); // bits per block (1.16/1.17 minimum is 4, not 0)
        let _ = VarInt(1).encode(&mut cd); // palette length
        let _ = VarInt(0).encode(&mut cd); // palette[0] = minecraft:air
                                           // 4 bits × 4096 cells = 256 longs, all zero → every cell is palette idx 0.
        let _ = VarInt(256).encode(&mut cd); // data long count
        for _ in 0..256 {
            cd.put_i64(0);
        }
    }
    let _ = VarInt(cd.len() as i32).encode(&mut body);
    body.put_slice(&cd);

    // Block entities (NAMED_COMPOUND_TAG_ARRAY): none.
    let _ = VarInt(0).encode(&mut body);
    body
}

/// Builds the void `LightUpdate` packet body for 1.17 / 1.17.1 (proto 755/756).
///
/// Mirrors the light trailer of the 1.18 combined chunk but as its own packet
/// with a `[VarInt x][VarInt z]` prefix (per ViaVersion
/// `WorldPacketRewriter1_17` LIGHT_UPDATE). Every light section is declared
/// explicitly empty (all-lit, zero data) so the client treats the void chunk
/// as fully lit instead of rendering it pitch black.
pub(crate) fn light_update_body_1_17(sections: usize) -> BytesMut {
    use kojacoord_protocol::codec::Encode;
    use kojacoord_protocol::types::VarInt;

    let mut body = BytesMut::new();
    let _ = VarInt(0).encode(&mut body); // chunk x
    let _ = VarInt(0).encode(&mut body); // chunk z
    body.put_u8(1); // trust edges

    let light_sections = sections + 2;
    let empty_mask: i64 = if light_sections >= 64 {
        -1
    } else {
        ((1u64 << light_sections) - 1) as i64
    };

    // sky / block light masks: no data sections.
    let _ = VarInt(0).encode(&mut body); // skyLightMask
    let _ = VarInt(0).encode(&mut body); // blockLightMask
                                         // empty masks: one long each, covering every light section.
    let _ = VarInt(1).encode(&mut body);
    body.put_i64(empty_mask); // emptySkyLightMask
    let _ = VarInt(1).encode(&mut body);
    body.put_i64(empty_mask); // emptyBlockLightMask
                              // No actual light arrays.
    let _ = VarInt(0).encode(&mut body); // sky light array count
    let _ = VarInt(0).encode(&mut body); // block light array count
    body
}

/// Writes a `MOTION_BLOCKING` long-array field of 37 zeroed `i64` values into an open NBT compound.
///
/// The field is encoded as: TAG_Long_Array (0x0C), a u16 name length and name bytes for `"MOTION_BLOCKING"`,
/// a i32 length `37`, followed by 37 `i64(0)` entries. Call this while an NBT compound is already open.
///
/// # Examples
///
/// ```ignore
/// use bytes::BytesMut;
/// // create an open compound: TAG_Compound (0x0a) then empty name
/// let mut buf = BytesMut::new();
/// buf.put_u8(0x0a);
/// buf.put_u16(0);
/// put_motion_blocking_field(&mut buf);
/// // close compound
/// buf.put_u8(0x00);
/// // buf now contains a compound with a MOTION_BLOCKING long-array of 37 zeros
/// assert!(buf.len() > 0);
/// ```
/// Body for `Set Default Spawn Position`: a packed `[Position]` long
/// (world spawn at origin 0,0,0) followed by a `[Float]` angle (0.0).
/// Position packing matches Mojang's `BlockPos.asLong`:
/// `((x & 0x3FFFFFF) << 38) | ((z & 0x3FFFFFF) << 12) | (y & 0xFFF)` —
/// the origin packs to 0. The actual coordinate is irrelevant to limbo;
/// the packet's presence is what dismisses the 1.19.3+ loading screen.
pub(crate) fn default_spawn_body() -> BytesMut {
    let mut body = BytesMut::new();
    body.put_i64(0); // packed Position (0, 0, 0)
    body.put_f32(0.0); // angle
    body
}

fn put_motion_blocking_field(body: &mut BytesMut) {
    body.put_u8(0x0c); // TAG_Long_Array
    let name = b"MOTION_BLOCKING";
    body.put_u16(name.len() as u16);
    body.put_slice(name);
    body.put_i32(37);
    for _ in 0..37 {
        body.put_i64(0);
    }
}

// Canonical buckets — own struct construction logic.
pub mod v1_12;
pub mod v1_16;
pub mod v1_19;
pub mod v1_20;
pub mod v1_21;
pub mod v1_6;
pub mod v1_7;
pub mod v1_8;
pub mod v26;

// Minor-version aliases — each re-exports its canonical bucket so
// downstream code can name the version directly. (1.9.x/1.10.x/1.11.x →
// v1_12; 1.13.x/1.14.x/1.15.x → v1_16; 1.17.x/1.18.x → v1_19.)
pub mod v1_10;
pub mod v1_11;
pub mod v1_13;
pub mod v1_14;
pub mod v1_15;
pub mod v1_17;
pub mod v1_18;
pub mod v1_9;

/// A wire-encoded limbo packet — packet id followed by the body.
/// The handler will prepend the VarInt(id) and frame the result.
pub struct EncodedPacket {
    pub id: u8,
    pub body: BytesMut,
}

/// Position emitted by `send_player_position`.
#[derive(Debug, Clone, Copy)]
pub struct PlayerPos {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub yaw: f32,
    pub pitch: f32,
}

/// Sound parameters. The exact id-vs-name mapping varies per version;
/// the impl picks whichever its struct expects.
#[derive(Debug, Clone, Copy)]
pub struct SoundParams {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub volume: f32,
    pub pitch: f32,
}

/// Every method takes `proto` (the negotiated wire protocol number)
/// because each canonical bucket spans several protocol numbers and the
/// returned id is looked up through the central registry, which keys on
/// the exact proto. Returns `None` if this version doesn't support that
/// packet (e.g. SystemChat on 1.17/1.18, BossBar on pre-1.9).
pub trait LimboPackets: Send + Sync {
    /// Build the initial JoinGame / Login packet (limbo flat world).
    fn join_game(&self, proto: u32, world_name: &str) -> Option<EncodedPacket>;

    /// Build a Respawn packet — used both when leaving limbo and when
    /// transitioning between worlds.
    fn respawn(&self, proto: u32, world_name: &str) -> Option<EncodedPacket>;

    /// Build a PlayerAbilities packet (flight, etc.).
    fn player_abilities(&self, proto: u32) -> Option<EncodedPacket>;

    /// Build a HeldItemChange / SetCarriedItem (slot 0).
    fn held_item_change(&self, proto: u32) -> Option<EncodedPacket>;

    /// Build a PlayerPosition packet anchoring the client to limbo.
    fn player_position(
        &self,
        proto: u32,
        pos: PlayerPos,
        teleport_id: i32,
    ) -> Option<EncodedPacket>;

    /// Build a chat / system-chat message.
    fn chat(&self, proto: u32, json_message: &str) -> Option<EncodedPacket>;

    /// Build a note-block sound effect at the limbo location.
    fn note_sound(&self, proto: u32, pos: SoundParams) -> Option<EncodedPacket>;

    /// Build a BossBar Add packet (or None for versions without bossbars).
    fn bossbar_add(&self, proto: u32, uuid: Uuid, title: &str) -> Option<EncodedPacket>;

    /// Build a BossBar Remove packet for the given uuid.
    fn bossbar_remove(&self, proto: u32, uuid: Uuid) -> Option<EncodedPacket>;

    /// Build a KeepAlive packet for the given id.
    fn keepalive(&self, proto: u32, id: i64) -> Option<EncodedPacket>;

    /// Build a clientbound PluginMessage containing the server brand.
    fn brand(&self, proto: u32, brand: &str) -> Option<EncodedPacket>;

    /// Constructs a SetChunkCacheCenter (Update View Position) packet that sets the chunk-cache center to chunk (0, 0).
    ///
    /// This packet ensures the client will accept and retain subsequently received chunks around that center; without it some clients may discard the void chunk and remain stuck in "Loading terrain".
    ///
    /// # Parameters
    ///
    /// - `proto`: negotiated wire protocol number used to select the appropriate packet id/format for the target client version.
    ///
    /// # Returns
    ///
    /// `Some(EncodedPacket)` containing the encoded SetChunkCacheCenter packet for the given protocol, or `None` if the protocol does not use this packet.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // `my_impl` implements `LimboPackets`
    /// let pkt = my_impl.set_center_chunk(763);
    /// if let Some(encoded) = pkt {
    ///     // send or inspect `encoded`
    /// }
    /// ```
    fn set_center_chunk(&self, _proto: u32) -> Option<EncodedPacket> {
        None
    }

    /// Builds a `Set Default Spawn Position` packet (world spawn at the
    /// origin, angle 0).
    ///
    /// REQUIRED from 1.19.3 (proto 761) onward: at 1.19.3 Mojang's
    /// `LevelLoadStatusManager` began gating the dismissal of the
    /// "Loading terrain" (`ReceivingLevelScreen`) on having received a
    /// default spawn position — sending only the chunk + player position
    /// (which sufficed through 1.19.2) leaves 1.19.3–1.20.2 clients stuck
    /// on the loading screen even though chunks and sounds arrive fine.
    /// 1.20.3+ (proto 765+) close the screen via the GameEvent-13
    /// "start waiting for level chunks" packet instead, so this is the
    /// closing mechanism for the 761–764 window specifically. Mirrors
    /// NanoLimbo `ClientConnection::spawnPlayer`, which emits
    /// `PACKET_SPAWN_POSITION` for every client `>= V1_19_3`.
    ///
    /// Body: `[Position location][Float angle]`. Returns `None` for
    /// versions that don't need it (pre-1.19.3, where the default impl
    /// applies).
    fn set_default_spawn(&self, _proto: u32) -> Option<EncodedPacket> {
        None
    }

    /// ```ignore
    fn chunk_batch_start(&self, _proto: u32) -> Option<EncodedPacket> {
        None
    }

    /// Builds a `ChunkBatchFinished` packet that carries the number of chunks in the batch for protocols that support it (1.20.2+).
    ///
    /// The returned packet, when present, should be sent to the client; the client will reply with an acknowledgement which this codebase ignores.
    ///
    /// # Parameters
    ///
    /// - `batch_size`: the number of chunks included in the finished batch.
    ///
    /// # Returns
    ///
    /// `Some(EncodedPacket)` with the encoded packet id and body when the protocol exposes this packet, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // For a protocol that supports ChunkBatchFinished (1.20.2+)
    /// let pkt = v1_20::V1_20.chunk_batch_finished(764, 16);
    /// assert!(pkt.is_some());
    /// ```
    fn chunk_batch_finished(&self, _proto: u32, _batch_size: i32) -> Option<EncodedPacket> {
        None
    }

    /// Builds the GameEvent packet (event ID 13) that tells the client to stop showing the "Loading terrain" screen.
    ///
    /// This packet is required beginning with protocol 765 (Minecraft 1.20.3+); for older protocol numbers this method returns `None`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Example usage: protocol 765 and newer produce a packet, older protocols do not.
    /// # let svc = &crate::net::limbo_packets::v1_21::V1_21;
    /// let _ = svc.start_wait_chunks_event(765); // Some(EncodedPacket)
    /// let _ = svc.start_wait_chunks_event(760); // None
    /// ```
    fn start_wait_chunks_event(&self, _proto: u32) -> Option<EncodedPacket> {
        None
    }

    /// Build a single void (all-air) level chunk at coordinates (0, 0) encoded as a `LevelChunkWithLight`.
    ///
    /// This chunk is intended for limbo use so clients receive at least the chunk containing the player; some modern clients (1.18+) remain on the loading screen until that chunk arrives. Implementations may return `None` when the canonical version does not synthesize void chunks.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Select a canonical bucket and request its limbo chunk for a protocol.
    /// let pkt = v1_20::V1_20.chunk_data(763);
    /// // Modern canonical buckets that implement void chunk synthesis should return Some(EncodedPacket).
    /// assert!(pkt.is_some());
    /// ```
    fn chunk_data(&self, _proto: u32) -> Option<EncodedPacket> {
        None
    }

    /// Build a standalone `LightUpdate` packet for the void chunk at (0, 0).
    ///
    /// Only 1.17 / 1.17.1 (proto 755/756) need this: they predate the 1.18
    /// combined chunk+light packet, so light must be sent separately. Every
    /// other bucket folds light into [`chunk_data`] and returns `None` here.
    fn light_update(&self, _proto: u32) -> Option<EncodedPacket> {
        None
    }

    /// 1.6.x-only essentials. Returning `None` by default makes the
    /// other canonical buckets no-op these — modern clients don't
    /// need a SpawnPosition broadcast to render their HUD; they take
    /// it from the JoinGame coordinate fields directly.
    ///
    /// `spawn_position`: tells pre-netty clients where the compass
    /// should point. Without it the compass UI stays blank.
    fn spawn_position(&self, _proto: u32, _pos: PlayerPos) -> Option<EncodedPacket> {
        None
    }

    /// `time_update`: pre-netty world stays at midnight (black sky)
    /// without a TimeUpdate. Modern clients use a different packet
    /// shape per epoch — limbo doesn't need to send it on those.
    fn time_update(&self, _proto: u32) -> Option<EncodedPacket> {
        None
    }

    /// `update_health`: pre-netty clients render the respawn screen
    /// (and reject input) until they see UpdateHealth with `health > 0`.
    /// Modern clients seed their HUD from JoinGame.
    fn update_health(&self, _proto: u32) -> Option<EncodedPacket> {
        None
    }
}

/// Static dispatch: pick the [`LimboPackets`] implementation that
/// matches `canonical` once at construction time, then call its
/// methods on the hot path.
pub fn for_version(canonical: CanonicalVersion) -> &'static dyn LimboPackets {
    match canonical {
        CanonicalVersion::V1_6_4 => &v1_6::V1_6,
        CanonicalVersion::V1_7_10 => &v1_7::V1_7,
        CanonicalVersion::V1_8 => &v1_8::V1_8,
        CanonicalVersion::V1_12_2 | CanonicalVersion::V1_15_2 => &v1_12::V1_12,
        CanonicalVersion::V1_16_5 | CanonicalVersion::V1_18_2 => &v1_16::V1_16,
        CanonicalVersion::V1_19_4 => &v1_19::V1_19,
        CanonicalVersion::V1_20_4 => &v1_20::V1_20,
        CanonicalVersion::V1_21 => &v1_21::V1_21,
        CanonicalVersion::V26 => &v26::V26,
    }
}

/// Encode a typed packet into an `EncodedPacket` using the packet's protocol id and its wire encoding.
///
/// Returns `None` when the packet id for the given `proto` is `0xFF` or when encoding fails.
///
/// # Examples
///
/// ```ignore
/// use bytes::BytesMut;
/// // `MyPkt` must implement `kojacoord_protocol::codec::PacketId` and `kojacoord_protocol::codec::Encode`.
/// // The call below returns `Some(EncodedPacket)` when the packet id is not 0xFF and encoding succeeds.
/// let proto: u32 = 763;
/// let pkt = MyPkt::new();
/// let encoded = crate::net::limbo_packets::encode(proto, pkt);
/// ```
pub(crate) fn encode<T: kojacoord_protocol::codec::Encode + kojacoord_protocol::codec::PacketId>(
    proto: u32,
    pkt: T,
) -> Option<EncodedPacket> {
    let id = T::packet_id(proto);
    if id == 0xFF {
        return None;
    }
    let mut body = BytesMut::new();
    pkt.encode(&mut body).ok()?;
    Some(EncodedPacket { id, body })
}

#[cfg(test)]
mod chunk_tests {
    use super::*;
    use bytes::Buf;
    use kojacoord_protocol::codec::Decode;
    use kojacoord_protocol::types::VarInt;

    /// Asserts that a generated void LevelChunkWithLight body parses exactly as expected for a given
    /// heightmap format and trust_edges flag.
    ///
    /// This test helper builds a void chunk body at (0,0) with `sections` sections using
    /// `void_chunk_body` and verifies the wire-format fields (coordinates, heightmaps, chunk data
    /// length/content, block entity count, optional trust_edges byte, light masks and arrays) are
    /// present and fully consumed.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Validate parsing for 24 sections, trust_edges = true, using named NBT heightmaps.
    /// assert_parses(24, true, HeightmapFmt::NamedNbt);
    /// ```
    fn assert_parses(sections: usize, trust_edges: bool, hm: HeightmapFmt) {
        let body = void_chunk_body(sections, trust_edges, hm);
        let mut b = body.freeze();
        assert_eq!(b.get_i32(), 0);
        assert_eq!(b.get_i32(), 0);
        match hm {
            HeightmapFmt::NamedNbt => {
                assert_eq!(b.get_u8(), 0x0a); // compound
                let nl = b.get_u16(); // empty name
                b.advance(nl as usize);
                // MOTION_BLOCKING long array field
                assert_eq!(b.get_u8(), 0x0c);
                let knl = b.get_u16();
                b.advance(knl as usize);
                let n = b.get_i32();
                b.advance(n as usize * 8);
                assert_eq!(b.get_u8(), 0x00); // end
            },
            HeightmapFmt::AnonNbt => {
                assert_eq!(b.get_u8(), 0x0a); // compound, no name
                assert_eq!(b.get_u8(), 0x0c);
                let knl = b.get_u16();
                b.advance(knl as usize);
                let n = b.get_i32();
                b.advance(n as usize * 8);
                assert_eq!(b.get_u8(), 0x00);
            },
            HeightmapFmt::Array => {
                assert_eq!(VarInt::decode(&mut b).unwrap().0, 0); // empty array
            },
        }
        let cd = VarInt::decode(&mut b).unwrap().0 as usize;
        assert_eq!(cd, sections * 8, "8 bytes per empty section");
        b.advance(cd);
        assert_eq!(VarInt::decode(&mut b).unwrap().0, 0); // block entities
        if trust_edges {
            assert_eq!(b.get_u8(), 1);
        }
        assert_eq!(VarInt::decode(&mut b).unwrap().0, 0); // skyLightMask (no data)
        assert_eq!(VarInt::decode(&mut b).unwrap().0, 0); // blockLightMask
                                                          // emptySkyLightMask: 1 long covering all `sections + 2` light sections
        assert_eq!(VarInt::decode(&mut b).unwrap().0, 1);
        let expected = if sections + 2 >= 64 {
            -1i64
        } else {
            ((1u64 << (sections + 2)) - 1) as i64
        };
        assert_eq!(
            b.get_i64(),
            expected,
            "emptySkyLightMask covers all sections"
        );
        assert_eq!(VarInt::decode(&mut b).unwrap().0, 1); // emptyBlockLightMask
        assert_eq!(b.get_i64(), expected);
        assert_eq!(VarInt::decode(&mut b).unwrap().0, 0); // sky light arrays
        assert_eq!(VarInt::decode(&mut b).unwrap().0, 0); // block light arrays
        assert_eq!(b.remaining(), 0, "no trailing bytes");
    }

    #[test]
    fn void_chunk_all_eras_parse() {
        assert_parses(24, true, HeightmapFmt::NamedNbt); // ≤1.19.4 style
        assert_parses(24, false, HeightmapFmt::NamedNbt); // 1.20/1.20.1
        assert_parses(24, false, HeightmapFmt::AnonNbt); // 1.20.2-1.21.4
        assert_parses(24, false, HeightmapFmt::Array); // 1.21.5+
    }

    /// 1.20/1.20.1 (763) JoinGame must carry the inline registry codec
    /// and fully parse (the 1.19.4 shape + trailing portal_cooldown).
    #[test]
    fn proto_763_join_game_has_inline_codec_and_parses() {
        use kojacoord_protocol::types::nbt::Nbt;

        let pkt = v1_20::V1_20
            .join_game(763, "minecraft:overworld")
            .expect("763 join");
        let mut b = pkt.body.clone().freeze();
        let _eid = b.get_i32();
        let _hc = b.get_u8();
        let _gm = b.get_u8();
        let _pgm = b.get_i8();
        let dc = VarInt::decode(&mut b).unwrap().0;
        for _ in 0..dc {
            let _ = String::decode(&mut b).unwrap();
        }
        Nbt::decode(&mut b).expect("inline registry codec decodes");
        let _dt = String::decode(&mut b).expect("dimension_type");
        let _dn = String::decode(&mut b).expect("dimension_name");
        let _seed = b.get_i64();
        let _max = VarInt::decode(&mut b).unwrap();
        let _vd = VarInt::decode(&mut b).unwrap();
        let _sd = VarInt::decode(&mut b).unwrap();
        let _rdi = b.get_u8();
        let _ers = b.get_u8();
        let _dbg = b.get_u8();
        let _flat = b.get_u8();
        let _death = b.get_u8();
        let _portal = VarInt::decode(&mut b).unwrap();
        assert_eq!(b.remaining(), 0, "763 JoinGame not fully consumed");
    }

    /// Set Default Spawn Position must be emitted for 1.19.3+ (proto
    /// 761+) — the packet that dismisses the "Loading terrain" screen —
    /// with the per-proto ids from ViaVersion, and MUST be absent for
    /// ≤1.19.2 (≤760), which don't need it. Body is a packed Position
    /// long + Float angle = 12 bytes.
    #[test]
    fn set_default_spawn_present_from_1_19_3() {
        use super::LimboPackets;
        // ≤1.19.2: not needed.
        assert!(v1_19::V1_19.set_default_spawn(759).is_none(), "1.19");
        assert!(v1_19::V1_19.set_default_spawn(760).is_none(), "1.19.2");
        // 1.19.3 / 1.19.4 (v1_19 bucket).
        for (proto, id) in [(761u32, 0x4cu8), (762, 0x50)] {
            let pkt = v1_19::V1_19
                .set_default_spawn(proto)
                .unwrap_or_else(|| panic!("proto {proto} must send spawn pos"));
            assert_eq!(pkt.id, id, "proto {proto} spawn-pos id");
            assert_eq!(pkt.body.len(), 12, "proto {proto} body = i64 + f32");
        }
        // 1.20 – 1.20.6 (v1_20 bucket).
        for (proto, id) in [(763u32, 0x50u8), (764, 0x52), (765, 0x54), (766, 0x56)] {
            let pkt = v1_20::V1_20
                .set_default_spawn(proto)
                .unwrap_or_else(|| panic!("proto {proto} must send spawn pos"));
            assert_eq!(pkt.id, id, "proto {proto} spawn-pos id");
            assert_eq!(pkt.body.len(), 12, "proto {proto} body");
        }
    }

    #[test]
    fn v1_20_v1_21_chunk_and_center_build() {
        // Every modern proto must yield a chunk + center packet.
        for proto in [763u32, 764, 765, 766] {
            assert!(
                v1_20::V1_20.chunk_data(proto).is_some(),
                "v1_20 chunk {proto}"
            );
            assert!(
                v1_20::V1_20.set_center_chunk(proto).is_some(),
                "v1_20 center {proto}"
            );
        }
        for proto in [767u32, 768, 769, 770, 771, 772, 773, 774] {
            assert!(
                v1_21::V1_21.chunk_data(proto).is_some(),
                "v1_21 chunk {proto}"
            );
            assert!(
                v1_21::V1_21.set_center_chunk(proto).is_some(),
                "v1_21 center {proto}"
            );
        }
        // batching only 764+, game event only 765+
        assert!(v1_20::V1_20.chunk_batch_start(763).is_none());
        assert!(v1_20::V1_20.chunk_batch_start(764).is_some());
        assert!(v1_20::V1_20.start_wait_chunks_event(764).is_none());
        assert!(v1_20::V1_20.start_wait_chunks_event(765).is_some());
        assert!(v1_21::V1_21.chunk_batch_start(770).is_some());
        assert!(v1_21::V1_21.start_wait_chunks_event(774).is_some());
    }
}
