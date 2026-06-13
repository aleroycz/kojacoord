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

/// Build a single void (all-air) `LevelChunkWithLight` body at chunk
/// (0,0). `sections` = world height / 16 (16 for 1.17, 24 for 1.18+).
/// `trust_edges` is the bool present only ≤ 1.19.4 (proto ≤ 762); 1.20+
/// dropped it. `hm` selects the heightmaps encoding for the proto era.
///
/// Empty sections use single-valued palettes (air block state 0, biome
/// registry id 0). Light is sent empty (all four masks + both arrays
/// zero-length); the void renders against sky/fog so per-block light is
/// unneeded. Wire shape verified against minecraft-data
/// `protocol.json::packet_map_chunk` across 1.18.2 → 1.21.3.
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

/// Write a `MOTION_BLOCKING: TAG_Long_Array[37]` (all zero) field into an
/// open NBT compound: `[tag 0x0c][u16 namelen][name][i32 len][len×i64]`.
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

    /// Build a `SetChunkCacheCenter` (Update View Position) at chunk
    /// (0,0). Modern clients (1.14+) only *store* a received chunk if it
    /// falls within the chunk-cache center's view radius; vanilla always
    /// sends this before the first chunk. Without it the void chunk is
    /// silently discarded and the client never leaves "Loading terrain".
    fn set_center_chunk(&self, _proto: u32) -> Option<EncodedPacket> {
        None
    }

    /// `ChunkBatchStart` (1.20.2+ / proto 764+). From 1.20.2 the client
    /// only processes chunks delivered inside a batch
    /// (`ChunkBatchStart` … chunks … `ChunkBatchFinished`). Older protos
    /// return None.
    fn chunk_batch_start(&self, _proto: u32) -> Option<EncodedPacket> {
        None
    }

    /// `ChunkBatchFinished` (1.20.2+) carrying the batch size (chunk
    /// count). The client replies with a serverbound ack we ignore.
    fn chunk_batch_finished(&self, _proto: u32, _batch_size: i32) -> Option<EncodedPacket> {
        None
    }

    /// `GameEvent` 13 "start waiting for level chunks" (1.20.3+ / proto
    /// 765+). This is what dismisses the "Loading terrain" screen from
    /// 1.20.3 onward (before that the chunk itself does). Older protos
    /// return None.
    fn start_wait_chunks_event(&self, _proto: u32) -> Option<EncodedPacket> {
        None
    }

    /// Build a single void (all-air) chunk at (0,0). Modern clients
    /// (1.18+) stay on the "Loading terrain" screen until they receive
    /// the chunk containing the player; a void limbo must send at least
    /// this one. Returns `None` for canonical buckets that don't yet
    /// synthesise a chunk (older epochs / not-yet-implemented eras), in
    /// which case the client may hang on the dirt screen.
    fn chunk_data(&self, _proto: u32) -> Option<EncodedPacket> {
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
        CanonicalVersion::V1_12_2 => &v1_12::V1_12,
        CanonicalVersion::V1_16_5 => &v1_16::V1_16,
        CanonicalVersion::V1_19_4 => &v1_19::V1_19,
        CanonicalVersion::V1_20_4 => &v1_20::V1_20,
        CanonicalVersion::V1_21 => &v1_21::V1_21,
    }
}

/// Helper used by every impl: encode a typed packet into an
/// [`EncodedPacket`] using `PacketId::packet_id(proto)` for the id and
/// `Encode::encode` for the body.
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

    /// Parse a void chunk body per the modern `LevelChunkWithLight` wire
    /// shape and assert it fully consumes for each heightmap era and
    /// trust_edges flag.
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
