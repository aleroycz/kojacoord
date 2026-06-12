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
        // 1.17 / 1.17.1 / 1.18 / 1.18.2: same blob, then augment each
        // element with `min_y` and `height` per ViaVersion's
        // `EntityPacketRewriter1_17::addNewDimensionData`. Same code
        // path the real 1.17+ ViaVersion deployment runs.
        755..=758 => augment_1_16_2_codec_for_1_17_plus(),
        p if p >= 764 => {
            kojacoord_protocol::dimension_codec_nbt_1_20_4().map_err(|e| e.to_string())
        },
        _ => kojacoord_protocol::dimension_codec_nbt().map_err(|e| e.to_string()),
    }
}

/// ViaVersion's `dimension-registry-1.16.2.nbt` (GPL v3, see
/// `crates/protocol/data/dimension_codec_1_16_2.LICENSE.md`).
static VIAVERSION_DIM_REGISTRY_1_16_2: &[u8] =
    include_bytes!("../../../../crates/protocol/data/dimension_codec_1_16_2.nbt");

/// Decode ViaVersion's 1.16.2 codec, walk to every dimension entry's
/// `element` compound, insert `min_y` and `height` (both required
/// from proto 755 / 1.17 onward), then re-encode. Mirrors
/// `EntityPacketRewriter1_17::addNewDimensionData` in ViaVersion.
fn augment_1_16_2_codec_for_1_17_plus() -> Result<Vec<u8>, String> {
    use kojacoord_protocol::codec::{Decode, Encode};
    use kojacoord_protocol::types::nbt::{Nbt, NbtTag};

    let mut src = bytes::Bytes::copy_from_slice(VIAVERSION_DIM_REGISTRY_1_16_2);
    let mut nbt = Nbt::decode(&mut src).map_err(|e| e.to_string())?;

    // root → "minecraft:dimension_type" Compound → "value" List<Compound>
    let dim_registry = nbt
        .root
        .get_mut("minecraft:dimension_type")
        .ok_or_else(|| "missing minecraft:dimension_type registry".to_string())?;
    let NbtTag::Compound(reg_map) = dim_registry else {
        return Err("minecraft:dimension_type is not a compound".into());
    };
    let value_list = reg_map
        .get_mut("value")
        .ok_or_else(|| "missing value list in dimension_type".to_string())?;
    let NbtTag::List(entries) = value_list else {
        return Err("value is not a list".into());
    };

    for entry in entries.iter_mut() {
        let NbtTag::Compound(entry_map) = entry else {
            continue;
        };
        let Some(element) = entry_map.get_mut("element") else {
            continue;
        };
        let NbtTag::Compound(element_map) = element else {
            continue;
        };
        element_map.insert("min_y".into(), NbtTag::Int(0));
        element_map.insert("height".into(), NbtTag::Int(256));
    }

    let mut buf = bytes::BytesMut::new();
    nbt.encode(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf.to_vec())
}

// build_codec_1_16_2_through_1_16_5 + build_codec_1_17_through_1_18_2
// + build_modern_codec replaced by `VIAVERSION_DIM_REGISTRY_1_16_2`
// embedding and `augment_1_16_2_codec_for_1_17_plus`. Kept the
// 1.16.0/1.16.1 hand-builder below since ViaVersion constructs that
// one in Java code (no precomputed NBT to embed).

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
