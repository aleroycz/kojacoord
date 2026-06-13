//! Dimension codec injection for cross-era JoinGame bridging.
//!
//! 1.16+ clients expect a dimension codec NBT embedded in JoinGame; 1.15
//! and earlier servers don't send one, and 1.20.2+ clients expect it
//! through the configuration phase instead. When the wire format on
//! both ends disagrees, we synthesise a minimal codec / dimension type
//! NBT here and splice it into the relayed packet stream so the client
//! has something to chew on.
//!
//! The synthesised values are deliberately minimal: one overworld
//! dimension, default biome registry. They're enough to keep the
//! client out of an error state until the real backend pushes its own
//! data — the proxy doesn't pretend to host a world.

use bytes::BytesMut;
use kojacoord_protocol::{
    types::{Nbt, NbtTag},
    Encode, ProtocolVersion,
};

/// True for 1.16+ clients that expect a dimension codec NBT on JoinGame.
pub fn uses_dimension_codec(protocol_version: u32) -> bool {
    let canonical = ProtocolVersion::from_id(protocol_version);
    matches!(
        canonical.epoch(),
        kojacoord_protocol::Epoch::V1_16
            | kojacoord_protocol::Epoch::V1_17_To_1_18
            | kojacoord_protocol::Epoch::V1_19
            | kojacoord_protocol::Epoch::V1_20
            | kojacoord_protocol::Epoch::V1_21Plus
    )
}

/// True when only one side of the bridge speaks the codec — we'll need
/// to synthesise it (or drop it) to keep them in sync.
pub fn needs_codec_injection(client_protocol: u32, backend_protocol: u32) -> bool {
    uses_dimension_codec(client_protocol) && !uses_dimension_codec(backend_protocol)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecInjectionMode {
    /// Both sides agree — pass JoinGame through unchanged.
    None,
    /// Client expects a codec the backend never produces; we inject
    /// one on the way to the client.
    ClientSide,
    /// Backend wants a codec from a client that doesn't have one
    /// (rare; mostly happens when bridging snapshots).
    BackendSide,
}

/// Decide which direction (if any) needs codec injection for the given
/// client/backend pair.
pub fn determine_injection_mode(client_protocol: u32, backend_protocol: u32) -> CodecInjectionMode {
    match (
        uses_dimension_codec(client_protocol),
        uses_dimension_codec(backend_protocol),
    ) {
        (true, false) => CodecInjectionMode::ClientSide,
        (false, true) => CodecInjectionMode::BackendSide,
        _ => CodecInjectionMode::None,
    }
}

/// Build a dimension codec NBT for the given protocol.
///
/// Per BungeeCord `protocol/Login.java`, the codec field exists from
/// proto 735 (1.16) onward and was removed when the Configuration
/// phase split out the registry data at proto 764 (1.20.2).
///
/// Strategy: prefer the byte-for-byte PrismarineJS codec for this
/// proto if `crates/protocol/data/dimension_codec_<proto>.nbt.bin`
/// was populated by `gen_dimension_codec`. Otherwise fall back to the
/// synthesised minimal codec which is enough to pass the client's
/// "did the server send a codec?" check but doesn't enumerate the
/// nether/end dimensions or the full biome registry.
pub fn build_dimension_codec_for_proto(proto: u32) -> Result<Vec<u8>, String> {
    // Per-era codec schema. Mojang restructured the dimension_codec
    // TWICE inside the 1.16-1.20 window:
    //
    //   proto 735, 736 (1.16 / 1.16.1):
    //       Top-level `dimension` TAG_List of `{key, element}` pairs.
    //       Element fields per the original 1.16 spec — no
    //       `effects` Identifier, no `coordinate_scale`.
    //
    //   proto 751 - 763 (1.16.2 - 1.19.4):
    //       Top-level `minecraft:dimension_type` registry +
    //       `minecraft:worldgen/biome` registry, each with `type`/
    //       `value` fields and per-entry `{name, id, element}`.
    //       Element has the full 15-field schema.
    //
    //   proto 764+ (1.20.2+):
    //       Same registry structure but extra fields on element
    //       (`monster_spawn_light_level`, etc.).
    //
    // The wrong schema → NBT parser overrun → following JoinGame
    // bytes get read as NBT data → eventually an Identifier String
    // is constructed from misaligned bytes → the client crashes
    // with `"Non [a-z0-9/_-] character in path of location:
    // minecraft:<garbage>"`. That's what 1.16/1.16.1 clients hit
    // when they were handed the 1.16.2+ schema.
    match proto {
        735 | 736 => build_codec_1_16_0_or_1_16_1(),
        // 1.16.2 - 1.16.5: ship ViaVersion's NBT blob verbatim. The
        // 1.16.5 client's `DimensionType.CODEC` MapCodec is strict
        // about field set / sub-structure, so we use the same bytes
        // ViaVersion uses (they've kept these protos working in
        // production for years against vanilla and modded clients).
        751..=754 => Ok(VIAVERSION_DIM_REGISTRY_1_16_2.to_vec()),
        // 1.17 / 1.17.1 / 1.18 / 1.18.2: authoritative minecraft-data
        // blobs (same approach as the 1.19 family below). The previous
        // "augment the 1.16.2 blob with min_y/height" path worked for
        // 1.17 (which still carries biome `depth`/`scale`/`category`)
        // but NOT 1.18/1.18.2: Mojang removed biome `depth`/`scale` in
        // 1.18, so the 1.16.2-derived biomes made the 1.18.x client
        // reject the registry and dump it (same SNBT-on-screen symptom
        // as the 1.19 regression). minecraft-data confirms: 1.17 biomes
        // keep depth/scale/category, 1.18/1.18.2 biomes drop depth/scale
        // (61-entry set starting `minecraft:the_void`). 1.17.1 has no
        // distinct minecraft-data entry — the 1.17 blob is wire-correct
        // for it.
        755 | 756 => Ok(DIM_CODEC_1_17.to_vec()),
        757 => Ok(DIM_CODEC_1_18.to_vec()),
        758 => Ok(DIM_CODEC_1_18_2.to_vec()),
        // 1.19 family (proto 759-763): ship the authoritative dimension
        // codec captured from a real vanilla server, via PrismarineJS
        // `minecraft-data` `pc/<ver>/loginPacket.json` → binary NBT.
        //
        // The previous approach (augment the 1.16.2 ViaVersion blob with
        // min_y/height/monster_spawn + a chat_type registry) produced a
        // STRUCTURALLY valid codec that the 1.19 client's strict registry
        // codecs still rejected, dumping the registry SNBT in a "received
        // invalid data" disconnect. Three independent reasons, all fixed
        // by using the real blob:
        //   * biome elements carried `depth`/`scale` (gone in 1.18) and
        //     `category` (gone in 1.19);
        //   * the biome *set* was the obsolete 1.16 list (no `the_void`,
        //     etc.) rather than the real 1.19 63-biome registry;
        //   * dimension `infiniburn` was `minecraft:infiniburn_overworld`
        //     but 1.18+ wants the block-tag form `#minecraft:...`.
        // The real blobs already include `minecraft:chat_type`,
        // `minecraft:dimension_type`, and `minecraft:worldgen/biome`
        // with the correct per-version shapes (1.19.4 switched biome
        // `precipitation` string → `has_precipitation` bool).
        759 => Ok(DIM_CODEC_1_19.to_vec()),
        760 | 761 => Ok(DIM_CODEC_1_19_2.to_vec()),
        762 => Ok(DIM_CODEC_1_19_4.to_vec()),
        // 1.20 / 1.20.1 (proto 763): adds the trim_pattern/trim_material
        // /damage_type registries on top of the 1.19.4 set. Still sent as
        // a single JoinGame codec (1.20.2+ moved registries to the
        // configuration phase — handled elsewhere).
        763 => Ok(DIM_CODEC_1_20.to_vec()),
        p if p >= 764 => {
            kojacoord_protocol::dimension_codec_nbt_1_20_4().map_err(|e| e.to_string())
        },
        _ => kojacoord_protocol::dimension_codec_nbt().map_err(|e| e.to_string()),
    }
}

/// Extract a single dimension's `element` compound from the proto's
/// registry codec and return it as a named (empty-name) network NBT —
/// the wire shape of the *inline* `dimension` field in the 1.16.2-1.18.2
/// JoinGame / Respawn packets.
///
/// The inline dimension MUST be byte-consistent with the dimension this
/// proto's registry actually defines (same `#`-tag `infiniburn`, same
/// `min_y`/`height`, etc.) or the client's strict `DimensionType` codec
/// rejects it — surfacing as a `Failed to decode` / dumped-element
/// disconnect. Deriving it from the same authoritative blob the registry
/// ships guarantees that consistency, instead of hand-synthesising a
/// second copy that drifts from the registry.
pub fn inline_dimension_nbt_for_proto(dim_key: &str, proto: u32) -> Result<Vec<u8>, String> {
    use kojacoord_protocol::codec::{Decode, Encode};
    use kojacoord_protocol::types::nbt::{Nbt, NbtTag};

    let codec = build_dimension_codec_for_proto(proto)?;
    let mut src = bytes::Bytes::copy_from_slice(&codec);
    let nbt = Nbt::decode(&mut src).map_err(|e| e.to_string())?;

    let NbtTag::Compound(dim_reg) = nbt
        .root
        .get("minecraft:dimension_type")
        .ok_or("codec missing minecraft:dimension_type")?
    else {
        return Err("dimension_type is not a compound".into());
    };
    let NbtTag::List(entries) = dim_reg.get("value").ok_or("dimension_type missing value")? else {
        return Err("dimension_type value is not a list".into());
    };
    let element = entries
        .iter()
        .find_map(|e| {
            let NbtTag::Compound(m) = e else { return None };
            match m.get("name") {
                Some(NbtTag::String(n)) if n == dim_key => m.get("element"),
                _ => None,
            }
        })
        .ok_or_else(|| format!("dimension {dim_key} not found in proto {proto} registry"))?;

    let NbtTag::Compound(element_map) = element else {
        return Err("dimension element is not a compound".into());
    };
    let inline = Nbt {
        name: String::new(),
        root: element_map.clone(),
    };
    let mut buf = bytes::BytesMut::new();
    inline.encode(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf.to_vec())
}

/// ViaVersion's `dimension-registry-1.16.2.nbt` (GPL v3, see
/// `crates/protocol/data/dimension_codec_1_16_2.LICENSE.md`).
static VIAVERSION_DIM_REGISTRY_1_16_2: &[u8] =
    include_bytes!("../../../../crates/protocol/data/dimension_codec_1_16_2.nbt");

/// Authoritative 1.19 / 1.19.2 / 1.19.4 dimension codecs, captured from
/// PrismarineJS `minecraft-data` `pc/<ver>/loginPacket.json` and
/// converted to binary (big-endian, named-root) NBT. Each contains the
/// full `minecraft:chat_type` + `minecraft:dimension_type` +
/// `minecraft:worldgen/biome` registries exactly as a vanilla server of
/// that version sends them in JoinGame. 1.19/1.19.2 use the
/// `precipitation` string biome shape; 1.19.4 uses `has_precipitation`.
static DIM_CODEC_1_17: &[u8] =
    include_bytes!("../../../../crates/protocol/data/dimension_codec_1_17.nbt");
static DIM_CODEC_1_18: &[u8] =
    include_bytes!("../../../../crates/protocol/data/dimension_codec_1_18.nbt");
static DIM_CODEC_1_18_2: &[u8] =
    include_bytes!("../../../../crates/protocol/data/dimension_codec_1_18_2.nbt");
static DIM_CODEC_1_19: &[u8] =
    include_bytes!("../../../../crates/protocol/data/dimension_codec_1_19.nbt");
static DIM_CODEC_1_19_2: &[u8] =
    include_bytes!("../../../../crates/protocol/data/dimension_codec_1_19_2.nbt");
static DIM_CODEC_1_19_4: &[u8] =
    include_bytes!("../../../../crates/protocol/data/dimension_codec_1_19_4.nbt");
static DIM_CODEC_1_20: &[u8] =
    include_bytes!("../../../../crates/protocol/data/dimension_codec_1_20.nbt");

// 1.17 - 1.20 codecs are now the authoritative minecraft-data blobs
// (`DIM_CODEC_1_17` … `DIM_CODEC_1_20`); the old
// `augment_1_16_2_codec_for_1_17_plus` synthesiser was removed because
// it carried the 1.16 biome set (wrong depth/scale for 1.18+).

// Kept the 1.16.0/1.16.1 hand-builder below — ViaVersion constructs
// it in Java code (no precomputed NBT for that era to embed).
#[allow(dead_code)]
fn build_modern_codec_unused_reference(add_height_fields: bool) -> Result<Vec<u8>, String> {
    use kojacoord_protocol::types::nbt::{Nbt, NbtTag};
    use std::collections::HashMap;

    let dim_element = |skylight: bool,
                       ceiling: bool,
                       ultrawarm: bool,
                       natural: bool,
                       infiniburn: &str,
                       effects: &str,
                       has_raids: bool,
                       fixed_time: Option<i64>|
     -> NbtTag {
        let mut m: HashMap<String, NbtTag> = HashMap::new();
        m.insert("piglin_safe".into(), NbtTag::Byte(0));
        m.insert("natural".into(), NbtTag::Byte(natural as i8));
        m.insert(
            "ambient_light".into(),
            NbtTag::Float(if skylight { 0.0 } else { 0.1 }),
        );
        m.insert("infiniburn".into(), NbtTag::String(infiniburn.into()));
        m.insert("respawn_anchor_works".into(), NbtTag::Byte(0));
        m.insert("has_skylight".into(), NbtTag::Byte(skylight as i8));
        m.insert("bed_works".into(), NbtTag::Byte(1));
        m.insert("effects".into(), NbtTag::String(effects.into()));
        m.insert("has_raids".into(), NbtTag::Byte(has_raids as i8));
        m.insert("logical_height".into(), NbtTag::Int(256));
        m.insert("coordinate_scale".into(), NbtTag::Double(1.0));
        m.insert("ultrawarm".into(), NbtTag::Byte(ultrawarm as i8));
        m.insert("has_ceiling".into(), NbtTag::Byte(ceiling as i8));
        if let Some(t) = fixed_time {
            m.insert("fixed_time".into(), NbtTag::Long(t));
        }
        if add_height_fields {
            m.insert("min_y".into(), NbtTag::Int(0));
            m.insert("height".into(), NbtTag::Int(256));
        }
        NbtTag::Compound(m)
    };
    let dim_entry = |name: &str, id: i32, element: NbtTag| -> NbtTag {
        let mut m: HashMap<String, NbtTag> = HashMap::new();
        m.insert("name".into(), NbtTag::String(name.into()));
        m.insert("id".into(), NbtTag::Int(id));
        m.insert("element".into(), element);
        NbtTag::Compound(m)
    };

    let overworld = dim_element(
        true,
        false,
        false,
        true,
        "minecraft:infiniburn_overworld",
        "minecraft:overworld",
        true,
        None,
    );
    let nether = dim_element(
        false,
        true,
        true,
        false,
        "minecraft:infiniburn_nether",
        "minecraft:the_nether",
        false,
        Some(18000),
    );
    let the_end = dim_element(
        false,
        false,
        false,
        false,
        "minecraft:infiniburn_end",
        "minecraft:the_end",
        true,
        Some(6000),
    );

    let mut dim_registry: HashMap<String, NbtTag> = HashMap::new();
    dim_registry.insert(
        "type".into(),
        NbtTag::String("minecraft:dimension_type".into()),
    );
    dim_registry.insert(
        "value".into(),
        NbtTag::List(vec![
            dim_entry("minecraft:overworld", 0, overworld),
            dim_entry("minecraft:the_nether", 1, nether),
            dim_entry("minecraft:the_end", 2, the_end),
        ]),
    );

    // Minimal biome registry — single plains entry is enough for the
    // codec validity check; we don't render real terrain in limbo.
    let mut biome_element: HashMap<String, NbtTag> = HashMap::new();
    biome_element.insert("precipitation".into(), NbtTag::String("rain".into()));
    biome_element.insert("depth".into(), NbtTag::Float(0.125));
    biome_element.insert("temperature".into(), NbtTag::Float(0.8));
    biome_element.insert("scale".into(), NbtTag::Float(0.05));
    biome_element.insert("downfall".into(), NbtTag::Float(0.4));
    biome_element.insert("category".into(), NbtTag::String("plains".into()));
    let mut biome_effects: HashMap<String, NbtTag> = HashMap::new();
    biome_effects.insert("sky_color".into(), NbtTag::Int(7907327));
    biome_effects.insert("water_fog_color".into(), NbtTag::Int(329011));
    biome_effects.insert("fog_color".into(), NbtTag::Int(12638463));
    biome_effects.insert("water_color".into(), NbtTag::Int(4159204));
    biome_element.insert("effects".into(), NbtTag::Compound(biome_effects));

    let mut biome_entry: HashMap<String, NbtTag> = HashMap::new();
    biome_entry.insert("name".into(), NbtTag::String("minecraft:plains".into()));
    biome_entry.insert("id".into(), NbtTag::Int(1));
    biome_entry.insert("element".into(), NbtTag::Compound(biome_element));

    let mut biome_registry: HashMap<String, NbtTag> = HashMap::new();
    biome_registry.insert(
        "type".into(),
        NbtTag::String("minecraft:worldgen/biome".into()),
    );
    biome_registry.insert(
        "value".into(),
        NbtTag::List(vec![NbtTag::Compound(biome_entry)]),
    );

    let mut root: HashMap<String, NbtTag> = HashMap::new();
    root.insert(
        "minecraft:dimension_type".into(),
        NbtTag::Compound(dim_registry),
    );
    root.insert(
        "minecraft:worldgen/biome".into(),
        NbtTag::Compound(biome_registry),
    );

    let nbt = Nbt {
        name: String::new(),
        root,
    };
    let mut buf = bytes::BytesMut::new();
    nbt.encode(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf.to_vec())
}

/// Hand-encode the 1.16 / 1.16.1 dimension_codec. Per minecraft.wiki
/// (archived Java_Edition_protocol/Packets#Join_Game 1.16 spec) the
/// top-level shape is a singular `dimension` TAG_List of `{key,
/// element}` pairs.
fn build_codec_1_16_0_or_1_16_1() -> Result<Vec<u8>, String> {
    use kojacoord_protocol::types::nbt::{Nbt, NbtTag};
    use std::collections::HashMap;

    // CRITICAL — 1.16.0 / 1.16.1 dimension entry shape is **FLAT**:
    // the identifier (`name`) and every dimension property
    // (`piglin_safe`, `bed_works`, `natural`, `ambient_light`,
    //  `infiniburn`, `respawn_anchor_works`, `has_skylight`, `bed_works`,
    //  `has_raids`, `logical_height`, `shrunk`, `ultrawarm`,
    //  `has_ceiling`) all live at the same Compound level. No nested
    // `element` wrapper.
    //
    // The nested `{name, id, element}` shape — which most current
    // wiki revisions document — was introduced at 1.16.2 alongside
    // the codec restructuring. Using the nested form on 1.16.0 made
    // the client throw a flood of
    // `"No key has_raids in MapLike[{name:..., element:(...)}]"`
    // because its deserializer looks for the fields at the outer
    // level. Verified against the Notchian `DimensionType$1.16.0`
    // codec deserializer.
    // Mirrors ViaVersion's `DimensionRegistries1_16.java` byte-for-
    // byte. All four entries are required: overworld, overworld_caves,
    // the_nether, the_end. Mojang's 1.16.0 codec deserializer rejects
    // codecs that don't enumerate at least these vanilla dimensions
    // (the client validates the codec covers every possible world
    // dimension at registry construction time).
    let make_entry = |name: &str,
                      piglin_safe: i8,
                      natural: i8,
                      ambient_light: f32,
                      infiniburn: &str,
                      respawn_anchor_works: i8,
                      has_skylight: i8,
                      bed_works: i8,
                      fixed_time: Option<i64>,
                      has_raids: i8,
                      logical_height: i32,
                      shrunk: i8,
                      ultrawarm: i8,
                      has_ceiling: i8|
     -> NbtTag {
        let mut m: HashMap<String, NbtTag> = HashMap::new();
        m.insert("name".into(), NbtTag::String(name.into()));
        m.insert("piglin_safe".into(), NbtTag::Byte(piglin_safe));
        m.insert("natural".into(), NbtTag::Byte(natural));
        m.insert("ambient_light".into(), NbtTag::Float(ambient_light));
        m.insert("infiniburn".into(), NbtTag::String(infiniburn.into()));
        m.insert(
            "respawn_anchor_works".into(),
            NbtTag::Byte(respawn_anchor_works),
        );
        m.insert("has_skylight".into(), NbtTag::Byte(has_skylight));
        m.insert("bed_works".into(), NbtTag::Byte(bed_works));
        if let Some(t) = fixed_time {
            m.insert("fixed_time".into(), NbtTag::Long(t));
        }
        m.insert("has_raids".into(), NbtTag::Byte(has_raids));
        m.insert("logical_height".into(), NbtTag::Int(logical_height));
        m.insert("shrunk".into(), NbtTag::Byte(shrunk));
        m.insert("ultrawarm".into(), NbtTag::Byte(ultrawarm));
        m.insert("has_ceiling".into(), NbtTag::Byte(has_ceiling));
        NbtTag::Compound(m)
    };

    let dimension_list = NbtTag::List(vec![
        make_entry(
            "minecraft:overworld",
            0,
            1,
            0.0,
            "minecraft:infiniburn_overworld",
            0,
            1,
            1,
            None,
            1,
            256,
            0,
            0,
            0,
        ),
        make_entry(
            "minecraft:overworld_caves",
            0,
            1,
            0.0,
            "minecraft:infiniburn_overworld",
            0,
            1,
            1,
            None,
            1,
            256,
            0,
            0,
            1,
        ),
        make_entry(
            "minecraft:the_nether",
            1,
            0,
            0.1,
            "minecraft:infiniburn_nether",
            1,
            0,
            0,
            Some(18000),
            0,
            128,
            1,
            1,
            1,
        ),
        make_entry(
            "minecraft:the_end",
            0,
            0,
            0.0,
            "minecraft:infiniburn_end",
            0,
            0,
            0,
            Some(6000),
            1,
            256,
            0,
            0,
            0,
        ),
    ]);

    let mut root: HashMap<String, NbtTag> = HashMap::new();
    root.insert("dimension".into(), dimension_list);

    let nbt = Nbt {
        name: String::new(),
        root,
    };
    let mut buf = bytes::BytesMut::new();
    nbt.encode(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf.to_vec())
}

/// Build a minimal `minecraft:dimension_type` + `minecraft:worldgen/biome`
/// registry NBT — one overworld entry, default biome. Just enough to
/// pass the client's "did the server send a codec?" check.
///
/// **Now delegates to `kojacoord_protocol::dimension_codec_nbt`** —
/// the in-crate hand-rolled version below missed five required
/// dimension_type element fields (`piglin_safe`, `effects`,
/// `has_raids`, `logical_height`, `coordinate_scale`) that 1.16.2+
/// clients require to parse the NBT compound without overrun. The
/// kept-around body below is dead code retained only to document the
/// original structure; remove once nothing external references it.
pub fn build_minimal_dimension_codec() -> Result<Vec<u8>, String> {
    return kojacoord_protocol::dimension_codec_nbt().map_err(|e| e.to_string());
    #[allow(unreachable_code)]
    let mut codec_nbt = Nbt::empty("");

    // Build dimension_type registry
    let mut dimension_type = NbtTag::compound();
    dimension_type.as_compound_mut().unwrap().insert(
        "type".to_string(),
        NbtTag::string("minecraft:dimension_type"),
    );

    let mut value_list = NbtTag::list();
    if let Some(list) = value_list.as_list_mut() {
        // Overworld dimension
        let mut overworld = NbtTag::compound();
        if let Some(compound) = overworld.as_compound_mut() {
            compound.insert("name".to_string(), NbtTag::string("minecraft:overworld"));
            compound.insert("id".to_string(), NbtTag::int(0));

            let mut element = NbtTag::compound();
            if let Some(elem) = element.as_compound_mut() {
                elem.insert("height".to_string(), NbtTag::int(256));
                elem.insert("min_y".to_string(), NbtTag::int(0));
                elem.insert("has_ceiling".to_string(), NbtTag::byte(0));
                elem.insert("has_skylight".to_string(), NbtTag::byte(1));
                elem.insert("natural".to_string(), NbtTag::byte(1));
                elem.insert("ambient_light".to_string(), NbtTag::float(0.0));
                elem.insert(
                    "infiniburn".to_string(),
                    NbtTag::string("minecraft:infiniburn_overworld"),
                );
                elem.insert("respawn_anchor_works".to_string(), NbtTag::byte(0));
                elem.insert("ultrawarm".to_string(), NbtTag::byte(0));
                elem.insert("bed_works".to_string(), NbtTag::byte(1));
            }
            compound.insert("element".to_string(), element);
        }
        list.push(overworld);
    }
    dimension_type
        .as_compound_mut()
        .unwrap()
        .insert("value".to_string(), value_list);

    codec_nbt
        .root
        .insert("minecraft:dimension_type".to_string(), dimension_type);

    // Build biome registry
    let mut biome = NbtTag::compound();
    biome.as_compound_mut().unwrap().insert(
        "type".to_string(),
        NbtTag::string("minecraft:worldgen/biome"),
    );

    let mut biome_value_list = NbtTag::list();
    if let Some(list) = biome_value_list.as_list_mut() {
        // Plains biome
        let mut plains = NbtTag::compound();
        if let Some(compound) = plains.as_compound_mut() {
            compound.insert("name".to_string(), NbtTag::string("minecraft:plains"));
            compound.insert("id".to_string(), NbtTag::int(1));

            let mut element = NbtTag::compound();
            if let Some(elem) = element.as_compound_mut() {
                elem.insert("precipitation".to_string(), NbtTag::string("rain"));
                elem.insert("depth".to_string(), NbtTag::float(0.125));
                elem.insert("temperature".to_string(), NbtTag::float(0.8));
                elem.insert("scale".to_string(), NbtTag::float(0.05));
                elem.insert("downfall".to_string(), NbtTag::float(0.4));
                elem.insert("category".to_string(), NbtTag::string("plains"));
            }
            compound.insert("element".to_string(), element);
        }
        list.push(plains);
    }
    biome
        .as_compound_mut()
        .unwrap()
        .insert("value".to_string(), biome_value_list);

    codec_nbt
        .root
        .insert("minecraft:worldgen/biome".to_string(), biome);

    // Encode to bytes
    let mut buffer = BytesMut::new();
    codec_nbt
        .encode(&mut buffer)
        .map_err(|e| format!("Failed to encode dimension codec NBT: {}", e))?;

    Ok(buffer.to_vec())
}

/// Build the registry NBT 1.19+ clients expect alongside the dimension
/// codec — currently only `minecraft:chat_type` (translation key +
/// `sender`/`content` parameters), which is all the client checks during
/// JoinGame.
pub fn build_minimal_registry() -> Result<Vec<u8>, String> {
    let mut registry_nbt = Nbt::empty("");

    // Build chat_type registry
    let mut chat_type = NbtTag::compound();
    chat_type
        .as_compound_mut()
        .unwrap()
        .insert("type".to_string(), NbtTag::string("minecraft:chat_type"));

    let mut value_list = NbtTag::list();
    if let Some(list) = value_list.as_list_mut() {
        // Chat type
        let mut chat = NbtTag::compound();
        if let Some(compound) = chat.as_compound_mut() {
            compound.insert("name".to_string(), NbtTag::string("minecraft:chat"));
            compound.insert("id".to_string(), NbtTag::int(0));

            let mut element = NbtTag::compound();
            if let Some(elem) = element.as_compound_mut() {
                let mut chat_elem = NbtTag::compound();
                if let Some(c) = chat_elem.as_compound_mut() {
                    c.insert(
                        "translation_key".to_string(),
                        NbtTag::string("chat.type.text"),
                    );

                    let mut params = NbtTag::list();
                    if let Some(p) = params.as_list_mut() {
                        p.push(NbtTag::string("sender"));
                        p.push(NbtTag::string("content"));
                    }
                    c.insert("parameters".to_string(), params);
                }
                elem.insert("chat".to_string(), chat_elem);

                let mut narration_elem = NbtTag::compound();
                if let Some(n) = narration_elem.as_compound_mut() {
                    n.insert(
                        "translation_key".to_string(),
                        NbtTag::string("chat.type.text.narrate"),
                    );

                    let mut params = NbtTag::list();
                    if let Some(p) = params.as_list_mut() {
                        p.push(NbtTag::string("sender"));
                        p.push(NbtTag::string("content"));
                    }
                    n.insert("parameters".to_string(), params);
                }
                elem.insert("narration".to_string(), narration_elem);
            }
            compound.insert("element".to_string(), element);
        }
        list.push(chat);
    }
    chat_type
        .as_compound_mut()
        .unwrap()
        .insert("value".to_string(), value_list);

    registry_nbt
        .root
        .insert("minecraft:chat_type".to_string(), chat_type);

    // Encode to bytes
    let mut buffer = BytesMut::new();
    registry_nbt
        .encode(&mut buffer)
        .map_err(|e| format!("Failed to encode registry NBT: {}", e))?;

    Ok(buffer.to_vec())
}

/// Convenience alias for [`build_minimal_dimension_codec`]; kept for
/// call-site readability where "codec NBT" reads more naturally than
/// "minimal codec".
pub fn dimension_codec_nbt() -> Result<Vec<u8>, String> {
    build_minimal_dimension_codec()
}

/// Standalone dimension-type NBT (the inner element 1.16.2+ JoinGame
/// carries separately from the codec).
///
/// **DELEGATED to the protocol crate's `dimension_type_nbt`** — the
/// in-crate hand-rolled version that previously lived here had TWO
/// independent bugs the user's 1.16.5 client crash revealed:
///
/// 1. It included `min_y` / `height` fields and was missing five
///    others (`piglin_safe`, `effects`, `has_raids`, `logical_height`,
///    `coordinate_scale`) — completely the wrong field set for any
///    1.16.x or 1.17/1.18.x client.
///
/// 2. It wrapped the element in `{element: <fields>}` instead of
///    emitting the bare element compound. The 1.16.2+ JoinGame
///    inline dimension is the bare compound — the wrapper made the
///    client's deserializer hit `MapLike[{element:(…)}]` and ask
///    "No key piglin_safe / no key has_raids" etc. for every required
///    field, exactly the cascade of errors the user reported.
///
/// The protocol crate's version uses the well-formed
/// `dimension_type_element` (per-version field set per minecraft.wiki
/// + ViaVersion's reference) and writes the bare element compound at
///   the root — the correct wire shape.
pub fn dimension_type_nbt(dim_key: &str) -> Result<Vec<u8>, String> {
    kojacoord_protocol::dimension_type_nbt(dim_key).map_err(|e| e.to_string())
}

/// Proto-aware variant used by limbo for 1.16.2 - 1.19.4. 1.17+ gets
/// `min_y` + `height` appended; 1.16.2 - 1.16.5 does not.
pub fn dimension_type_nbt_for_proto(dim_key: &str, proto: u32) -> Result<Vec<u8>, String> {
    kojacoord_protocol::dimension_type_nbt_for_proto(dim_key, proto).map_err(|e| e.to_string())
}

#[cfg(test)]
mod ship_check {
    //! Smoke tests that fail loudly if the wrong codec bytes land in
    //! the binary. Specifically:
    //!   * proto 754 (1.16.5) MUST be byte-for-byte identical to the
    //!     embedded ViaVersion blob.
    //!   * proto 755 (1.17) MUST contain `min_y` + `height` field
    //!     names inserted by `augment_1_16_2_codec_for_1_17_plus`.
    //!
    //! If either of these tests fail in your CI but a running proxy
    //! still shows the old behaviour, the running .exe is stale (cargo
    //! couldn't replace it while the proxy held the file lock) —
    //! stop the proxy, run `cargo build --release`, then restart.

    use super::*;

    #[test]
    fn proto_754_matches_embedded_viaversion_blob_exactly() {
        let out = build_dimension_codec_for_proto(754).expect("must build");
        assert_eq!(
            out.as_slice(),
            VIAVERSION_DIM_REGISTRY_1_16_2,
            "1.16.5 codec must be byte-for-byte the ViaVersion blob",
        );
    }

    #[test]
    fn proto_755_contains_min_y_and_height_field_names() {
        let out = build_dimension_codec_for_proto(755).expect("must build");
        // Search for the UTF-8 NBT field name bytes (each preceded by
        // the i16 length prefix `0x00 0x05` for "min_y" and
        // `0x00 0x06` for "height").
        let needle_min_y: &[u8] = &[0x00, 0x05, b'm', b'i', b'n', b'_', b'y'];
        let needle_height: &[u8] = &[0x00, 0x06, b'h', b'e', b'i', b'g', b'h', b't'];
        assert!(
            out.windows(needle_min_y.len()).any(|w| w == needle_min_y),
            "1.17 codec must contain `min_y` field"
        );
        assert!(
            out.windows(needle_height.len()).any(|w| w == needle_height),
            "1.17 codec must contain `height` field"
        );
    }

    #[test]
    fn proto_754_does_not_contain_min_y() {
        let out = build_dimension_codec_for_proto(754).expect("must build");
        let needle_min_y: &[u8] = &[0x00, 0x05, b'm', b'i', b'n', b'_', b'y'];
        assert!(
            !out.windows(needle_min_y.len()).any(|w| w == needle_min_y),
            "1.16.5 codec must NOT contain min_y field (1.17+ only)"
        );
    }

    /// The inline dimension NBT (1.16.2+ JoinGame's second NBT) is the
    /// bare element compound — no `element:` wrapper. The previous
    /// hand-rolled `dimension_type_nbt` in proxy-core erroneously
    /// wrapped it as `{element: <fields>}`, causing the 1.16.5
    /// client to throw a cascade of "No key piglin_safe / has_raids
    /// / logical_height" errors. This test pins the bare-element
    /// shape by asserting `piglin_safe` appears near the start
    /// (right after the root Compound header) instead of after an
    /// `element` key prefix.
    /// 1.16.5 inline dimension must NOT contain `min_y`/`height`.
    #[test]
    fn inline_dim_754_has_no_min_y_or_height() {
        let out = dimension_type_nbt_for_proto("minecraft:overworld", 754).expect("must build");
        let min_y: &[u8] = &[0x00, 0x05, b'm', b'i', b'n', b'_', b'y'];
        let height: &[u8] = &[0x00, 0x06, b'h', b'e', b'i', b'g', b'h', b't'];
        assert!(
            !out.windows(min_y.len()).any(|w| w == min_y),
            "1.16.5 inline dim must NOT contain min_y"
        );
        assert!(
            !out.windows(height.len()).any(|w| w == height),
            "1.16.5 inline dim must NOT contain height"
        );
    }

    /// 1.17 inline dimension MUST contain `min_y` AND `height`. This
    /// is the exact field set the user's 1.17 client crash demanded.
    #[test]
    fn inline_dim_755_contains_min_y_and_height() {
        let out = dimension_type_nbt_for_proto("minecraft:overworld", 755).expect("must build");
        let min_y: &[u8] = &[0x00, 0x05, b'm', b'i', b'n', b'_', b'y'];
        let height: &[u8] = &[0x00, 0x06, b'h', b'e', b'i', b'g', b'h', b't'];
        assert!(
            out.windows(min_y.len()).any(|w| w == min_y),
            "1.17 inline dim MUST contain min_y"
        );
        assert!(
            out.windows(height.len()).any(|w| w == height),
            "1.17 inline dim MUST contain height"
        );
    }

    /// 1.19 codec MUST contain `minecraft:chat_type` registry,
    /// `monster_spawn_*` element fields, AND the 1.17 `min_y`/`height`.
    #[test]
    fn proto_759_codec_contains_chat_type_and_monster_spawn() {
        let out = build_dimension_codec_for_proto(759).expect("must build");
        let chat_type: &[u8] = &[
            0x00, 0x13, b'm', b'i', b'n', b'e', b'c', b'r', b'a', b'f', b't', b':', b'c', b'h',
            b'a', b't', b'_', b't', b'y', b'p', b'e',
        ];
        let monster_spawn_light: &[u8] = &[
            0x00, 0x19, b'm', b'o', b'n', b's', b't', b'e', b'r', b'_', b's', b'p', b'a', b'w',
            b'n', b'_', b'l', b'i', b'g', b'h', b't', b'_', b'l', b'e', b'v', b'e', b'l',
        ];
        let min_y: &[u8] = &[0x00, 0x05, b'm', b'i', b'n', b'_', b'y'];
        assert!(
            out.windows(chat_type.len()).any(|w| w == chat_type),
            "1.19 codec MUST contain minecraft:chat_type registry"
        );
        assert!(
            out.windows(monster_spawn_light.len())
                .any(|w| w == monster_spawn_light),
            "1.19 codec MUST contain monster_spawn_light_level on dim elements"
        );
        assert!(
            out.windows(min_y.len()).any(|w| w == min_y),
            "1.19 codec MUST contain min_y (1.17 carry-over)"
        );
    }

    /// The embedded 1.19 codec (from minecraft-data) must be the REAL
    /// 1.19 registry: biome elements carry none of the obsolete
    /// `depth`/`scale`/`category` fields, the biome SET is the modern
    /// one (contains `minecraft:the_void`, absent from the old 1.16
    /// blob), and the overworld dimension's `infiniburn` uses the
    /// 1.18+ block-tag form `#minecraft:...`. Any of these wrong made
    /// the 1.19 client reject the registry and dump it in a disconnect.
    #[test]
    fn proto_759_codec_is_authoritative_1_19() {
        use kojacoord_protocol::codec::Decode;
        use kojacoord_protocol::types::nbt::{Nbt, NbtTag};

        let codec = build_dimension_codec_for_proto(759).expect("build 759");
        let mut src = bytes::Bytes::copy_from_slice(&codec);
        let nbt = Nbt::decode(&mut src).expect("decode");
        assert_eq!(src.len(), 0, "codec must be exactly one NBT (no trailing)");

        // --- biomes ---
        let NbtTag::Compound(biome_reg) = nbt
            .root
            .get("minecraft:worldgen/biome")
            .expect("biome registry present")
        else {
            panic!("biome registry not a compound");
        };
        let NbtTag::List(biomes) = biome_reg.get("value").expect("value list") else {
            panic!("biome value not a list");
        };
        assert!(biomes.len() >= 60, "real 1.19 biome set is ~63 entries");
        let mut saw_the_void = false;
        for entry in biomes {
            let NbtTag::Compound(entry_map) = entry else {
                continue;
            };
            if let Some(NbtTag::String(name)) = entry_map.get("name") {
                if name == "minecraft:the_void" {
                    saw_the_void = true;
                }
            }
            let Some(NbtTag::Compound(element)) = entry_map.get("element") else {
                continue;
            };
            for banned in ["depth", "scale", "category"] {
                assert!(
                    !element.contains_key(banned),
                    "1.19 biome must not contain `{banned}`"
                );
            }
            assert!(element.contains_key("effects"), "biome must keep effects");
        }
        assert!(
            saw_the_void,
            "real 1.19 registry must contain minecraft:the_void"
        );

        // --- dimension infiniburn must be the #tag form ---
        let NbtTag::Compound(dim_reg) = nbt
            .root
            .get("minecraft:dimension_type")
            .expect("dimension_type present")
        else {
            panic!("dimension_type not a compound");
        };
        let NbtTag::List(dims) = dim_reg.get("value").expect("dim value list") else {
            panic!("dim value not a list");
        };
        for entry in dims {
            let NbtTag::Compound(entry_map) = entry else {
                continue;
            };
            let Some(NbtTag::Compound(element)) = entry_map.get("element") else {
                continue;
            };
            if let Some(NbtTag::String(inf)) = element.get("infiniburn") {
                assert!(
                    inf.starts_with('#'),
                    "1.19 dimension infiniburn must be a #block-tag, got `{inf}`"
                );
            }
        }

        // --- chat_type registry present (1.19 requires it) ---
        assert!(
            nbt.root.contains_key("minecraft:chat_type"),
            "1.19 codec must include minecraft:chat_type"
        );
    }

    /// The inline dimension NBT (used in the 1.17-1.18.2 JoinGame /
    /// Respawn) must be byte-consistent with its registry: a valid named
    /// NBT carrying min_y/height, and — crucially — the *version's own*
    /// `infiniburn` form. 1.17 still uses the bare `minecraft:...`
    /// identifier; 1.18 switched to the `#`-block-tag form. The old
    /// synthesiser emitted the bare form for ALL of 755-758, which the
    /// strict 1.18.x DimensionType codec rejected ("Failed to decode").
    /// Extracting from each proto's real blob fixes it automatically.
    #[test]
    fn inline_dimension_matches_registry_for_1_17_1_18() {
        use kojacoord_protocol::codec::Decode;
        use kojacoord_protocol::types::nbt::{Nbt, NbtTag};

        // The `#`-block-tag infiniburn form is 1.18.2-only (proto 758);
        // 1.17 (755) and 1.18.0 (757) still use the bare identifier.
        for (proto, want_tag_infiniburn) in [(755u32, false), (757, false), (758, true)] {
            let bytes = inline_dimension_nbt_for_proto("minecraft:overworld", proto)
                .unwrap_or_else(|e| panic!("proto {proto}: {e}"));
            let mut src = bytes::Bytes::copy_from_slice(&bytes);
            let nbt = Nbt::decode(&mut src).expect("inline dim decodes");
            assert_eq!(src.len(), 0, "proto {proto} inline dim has trailing bytes");
            let Some(NbtTag::String(inf)) = nbt.root.get("infiniburn") else {
                panic!("proto {proto} inline dim missing string infiniburn");
            };
            assert_eq!(
                inf.starts_with('#'),
                want_tag_infiniburn,
                "proto {proto} infiniburn `#`-tag expectation mismatch (got `{inf}`)"
            );
            assert!(
                nbt.root.contains_key("min_y") && nbt.root.contains_key("height"),
                "proto {proto} inline dim must have min_y/height (1.17+)"
            );
        }
    }

    /// Every wired JoinGame-codec proto (1.16.2 → 1.20.1) must decode
    /// to exactly one self-framing NBT with no trailing bytes, and
    /// contain the three core registries. Guards all embedded
    /// minecraft-data blobs at once against truncation / conversion bugs.
    #[test]
    fn all_wired_codecs_decode_cleanly() {
        use kojacoord_protocol::codec::Decode;
        use kojacoord_protocol::types::nbt::{Nbt, NbtTag};

        for proto in [751u32, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763] {
            let codec = build_dimension_codec_for_proto(proto)
                .unwrap_or_else(|e| panic!("proto {proto} build failed: {e}"));
            let mut src = bytes::Bytes::copy_from_slice(&codec);
            let nbt = Nbt::decode(&mut src)
                .unwrap_or_else(|e| panic!("proto {proto} NBT decode failed: {e}"));
            assert_eq!(src.len(), 0, "proto {proto} codec has trailing bytes");

            for reg in ["minecraft:dimension_type", "minecraft:worldgen/biome"] {
                assert!(nbt.root.contains_key(reg), "proto {proto} missing {reg}");
            }
            // chat_type registry only exists from 1.19 (proto 759).
            if proto >= 759 {
                assert!(
                    nbt.root.contains_key("minecraft:chat_type"),
                    "proto {proto} (1.19+) missing minecraft:chat_type"
                );
            }

            // biome depth/scale are gone from 1.18 (proto 757); category
            // is gone from 1.19 (proto 759). Verify the strip-by-version.
            let NbtTag::Compound(biome_reg) = nbt.root.get("minecraft:worldgen/biome").unwrap()
            else {
                panic!("proto {proto} biome registry not compound");
            };
            let NbtTag::List(biomes) = biome_reg.get("value").unwrap() else {
                panic!("proto {proto} biome value not list");
            };
            for entry in biomes {
                let NbtTag::Compound(em) = entry else {
                    continue;
                };
                let Some(NbtTag::Compound(el)) = em.get("element") else {
                    continue;
                };
                if proto >= 757 {
                    assert!(
                        !el.contains_key("depth") && !el.contains_key("scale"),
                        "proto {proto} biome must not have depth/scale (removed in 1.18)"
                    );
                }
                if proto >= 759 {
                    assert!(
                        !el.contains_key("category"),
                        "proto {proto} biome must not have category (removed in 1.19)"
                    );
                }
            }
        }
    }

    /// 1.19 inline dim MUST contain `monster_spawn_light_level`.
    #[test]
    fn inline_dim_759_contains_monster_spawn_light_level() {
        let out = dimension_type_nbt_for_proto("minecraft:overworld", 759).expect("must build");
        let needle: &[u8] = &[
            0x00, 0x19, b'm', b'o', b'n', b's', b't', b'e', b'r', b'_', b's', b'p', b'a', b'w',
            b'n', b'_', b'l', b'i', b'g', b'h', b't', b'_', b'l', b'e', b'v', b'e', b'l',
        ];
        assert!(
            out.windows(needle.len()).any(|w| w == needle),
            "1.19 inline dim MUST contain monster_spawn_light_level"
        );
    }

    /// 1.18.2 inline dim MUST NOT contain `monster_spawn_light_level`.
    #[test]
    fn inline_dim_758_no_monster_spawn_light_level() {
        let out = dimension_type_nbt_for_proto("minecraft:overworld", 758).expect("must build");
        let needle: &[u8] = &[
            0x00, 0x19, b'm', b'o', b'n', b's', b't', b'e', b'r', b'_', b's', b'p', b'a', b'w',
            b'n', b'_', b'l', b'i', b'g', b'h', b't', b'_', b'l', b'e', b'v', b'e', b'l',
        ];
        assert!(
            !out.windows(needle.len()).any(|w| w == needle),
            "1.18.2 inline dim must NOT contain monster_spawn_light_level (1.19+ only)"
        );
    }

    /// 1.18.2 inline dimension MUST contain `min_y` AND `height`.
    #[test]
    fn inline_dim_758_contains_min_y_and_height() {
        let out = dimension_type_nbt_for_proto("minecraft:overworld", 758).expect("must build");
        let min_y: &[u8] = &[0x00, 0x05, b'm', b'i', b'n', b'_', b'y'];
        let height: &[u8] = &[0x00, 0x06, b'h', b'e', b'i', b'g', b'h', b't'];
        assert!(
            out.windows(min_y.len()).any(|w| w == min_y),
            "1.18.2 inline dim MUST contain min_y"
        );
        assert!(
            out.windows(height.len()).any(|w| w == height),
            "1.18.2 inline dim MUST contain height"
        );
    }

    #[test]
    fn inline_dimension_type_is_bare_element_not_wrapped() {
        let out = dimension_type_nbt("minecraft:overworld").expect("must build");
        // Must NOT contain the bytes for an "element" field name at
        // root level. The buggy version wrote
        //   0x0A (Compound) 0x00 0x07 "element" …
        // i.e. an "element" String name appears immediately after the
        // Compound tag's empty root name.
        let element_field_name: &[u8] = &[0x00, 0x07, b'e', b'l', b'e', b'm', b'e', b'n', b't'];
        // The element field name would appear once at position 3+
        // (after `0x0A 0x00 0x00`) if wrapped. We forbid it appearing
        // ANYWHERE in the first 16 bytes since the root has no name
        // and the first child tag should be one of the actual element
        // fields, not an "element" wrapper.
        let head = &out[..16.min(out.len())];
        assert!(
            !head.windows(element_field_name.len()).any(|w| w == element_field_name),
            "inline dimension must be bare element compound, not {{element: …}}. Got prefix: {:02x?}",
            head
        );
        // Sanity: one of the real element fields must appear in the
        // payload (we don't pin order because Mojang's NBT compound
        // is unordered).
        let piglin_safe: &[u8] = &[
            0x00, 0x0B, b'p', b'i', b'g', b'l', b'i', b'n', b'_', b's', b'a', b'f', b'e',
        ];
        assert!(
            out.windows(piglin_safe.len()).any(|w| w == piglin_safe),
            "inline dimension must contain piglin_safe field"
        );
    }
}
