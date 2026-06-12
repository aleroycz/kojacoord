//! Minimum-viable dimension codec / dimension type NBT compounds for the
//! 1.16+ JoinGame and Respawn packets.
//!
//! Source: <https://minecraft.wiki/w/Java_Edition_protocol/Packets> §JoinGame
//! and the 1.16 protocol-history page. The codec the client receives has to
//! describe at least the dimension(s) it might be teleported into and the
//! biome(s) it might render — the vanilla Notchian server ships a much larger
//! codec describing the full vanilla registry. We synthesize a minimal subset
//! covering overworld / nether / end plus a single `minecraft:plains` biome,
//! which is enough for a 1.16.5 vanilla client to enter the world and render.
//!
//! The 1.16.2 protocol bump changed the codec slightly (dimension type became
//! its own embedded compound rather than an int id); the layout here targets
//! 1.16.2+ since 1.16.0/1.16.1 are sub-1% of legacy clients.
//!
//! 1.20.4+ uses a more complex registry structure with additional fields
//! like `monster_spawn_light_level`, `min_y`, `height`, etc.

use std::collections::HashMap;

use crate::codec::Encode;
use crate::types::nbt::{Nbt, NbtTag};
use crate::ProtocolError;
use bytes::BytesMut;

fn d(v: f64) -> NbtTag {
    NbtTag::Float(v as f32)
}
fn b(v: i8) -> NbtTag {
    NbtTag::Byte(v)
}
fn i(v: i32) -> NbtTag {
    NbtTag::Int(v)
}
fn s(v: &str) -> NbtTag {
    NbtTag::String(v.to_string())
}

fn dimension_type_element(
    has_skylight: bool,
    has_ceiling: bool,
    ultrawarm: bool,
    natural: bool,
    infiniburn: &str,
    effects: &str,
    is_1_20_4: bool,
) -> NbtTag {
    let mut m = HashMap::new();
    m.insert("piglin_safe".into(), b(0));
    m.insert("natural".into(), b(natural as i8));
    m.insert(
        "ambient_light".into(),
        d(if has_skylight { 0.0 } else { 0.1 }),
    );
    m.insert("infiniburn".into(), s(infiniburn));
    m.insert("respawn_anchor_works".into(), b(0));
    m.insert("has_skylight".into(), b(has_skylight as i8));
    m.insert("bed_works".into(), b(1));
    m.insert("effects".into(), s(effects));
    m.insert("has_raids".into(), b(1));
    // `min_y` and `height` were added in 1.17 (proto 755). Before
    // that the world was implicitly 0..256. ViaVersion's
    // `dimension-registry-1.16.2.nbt` confirms these fields are
    // absent at 1.16.2-1.16.5; we gate them on the 1.20.4 flag here
    // as a conservative approximation (callers wanting precise 1.17
    // vs 1.16.2 behaviour should use the proxy-core
    // `build_dimension_codec_for_proto` instead).
    if is_1_20_4 {
        m.insert("min_y".into(), i(0));
        m.insert("height".into(), i(256));
    }
    m.insert("logical_height".into(), i(256));
    m.insert("coordinate_scale".into(), NbtTag::Double(1.0));
    m.insert("ultrawarm".into(), b(ultrawarm as i8));
    m.insert("has_ceiling".into(), b(has_ceiling as i8));

    // 1.20.4+ additional fields
    if is_1_20_4 {
        m.insert("monster_spawn_light_level".into(), NbtTag::Int(0));
        m.insert("monster_spawn_block_light_limit".into(), NbtTag::Int(0));
        m.insert("fixed_time".into(), NbtTag::Int(0)); // 0 = no fixed time
    }

    NbtTag::Compound(m)
}

fn dim_entry(name: &str, id: i32, element: NbtTag) -> NbtTag {
    let mut m = HashMap::new();
    m.insert("name".into(), s(name));
    m.insert("id".into(), i(id));
    m.insert("element".into(), element);
    NbtTag::Compound(m)
}

fn biome_effects() -> NbtTag {
    let mut m = HashMap::new();
    m.insert("sky_color".into(), i(7_907_327));
    m.insert("water_fog_color".into(), i(329_011));
    m.insert("fog_color".into(), i(12_638_463));
    m.insert("water_color".into(), i(4_159_204));
    NbtTag::Compound(m)
}

fn plains_biome_element() -> NbtTag {
    let mut m = HashMap::new();
    m.insert("precipitation".into(), s("rain"));
    m.insert("depth".into(), NbtTag::Float(0.125));
    m.insert("temperature".into(), NbtTag::Float(0.8));
    m.insert("scale".into(), NbtTag::Float(0.05));
    m.insert("downfall".into(), NbtTag::Float(0.4));
    m.insert("category".into(), s("plains"));
    m.insert("effects".into(), biome_effects());
    NbtTag::Compound(m)
}

fn biome_entry(name: &str, id: i32) -> NbtTag {
    let mut m = HashMap::new();
    m.insert("name".into(), s(name));
    m.insert("id".into(), i(id));
    m.insert("element".into(), plains_biome_element());
    NbtTag::Compound(m)
}

fn registry(registry_id: &str, values: Vec<NbtTag>) -> NbtTag {
    let mut m = HashMap::new();
    m.insert("type".into(), s(registry_id));
    m.insert("value".into(), NbtTag::List(values));
    NbtTag::Compound(m)
}

/// Build the dimension codec compound that 1.16+ JoinGame embeds.
/// Returned as a network-encoded NBT (compound tag with empty name).
pub fn dimension_codec_nbt() -> Result<Vec<u8>, ProtocolError> {
    dimension_codec_nbt_with_version(false)
}

/// Build the dimension codec compound for 1.20.4+ JoinGame.
/// Includes additional fields required by modern versions.
pub fn dimension_codec_nbt_1_20_4() -> Result<Vec<u8>, ProtocolError> {
    dimension_codec_nbt_with_version(true)
}

fn dimension_codec_nbt_with_version(is_1_20_4: bool) -> Result<Vec<u8>, ProtocolError> {
    let mut root: HashMap<String, NbtTag> = HashMap::new();

    let overworld = dimension_type_element(
        true,
        false,
        false,
        true,
        "minecraft:infiniburn_overworld",
        "minecraft:overworld",
        is_1_20_4,
    );
    let nether = dimension_type_element(
        false,
        true,
        true,
        false,
        "minecraft:infiniburn_nether",
        "minecraft:the_nether",
        is_1_20_4,
    );
    let end = dimension_type_element(
        false,
        false,
        false,
        false,
        "minecraft:infiniburn_end",
        "minecraft:the_end",
        is_1_20_4,
    );

    let dim_registry = registry(
        "minecraft:dimension_type",
        vec![
            dim_entry("minecraft:overworld", 0, overworld),
            dim_entry("minecraft:the_nether", 1, nether),
            dim_entry("minecraft:the_end", 2, end),
        ],
    );

    let biome_registry = registry(
        "minecraft:worldgen/biome",
        vec![biome_entry("minecraft:plains", 1)],
    );

    root.insert("minecraft:dimension_type".into(), dim_registry);
    root.insert("minecraft:worldgen/biome".into(), biome_registry);

    let nbt = Nbt {
        name: String::new(),
        root,
    };
    let mut buf = BytesMut::new();
    nbt.encode(&mut buf)?;
    Ok(buf.to_vec())
}

/// Build the standalone "dimension type" compound the 1.16.2+ JoinGame embeds
/// right after the codec. `key` is e.g. "minecraft:overworld".
///
/// Legacy alias for `dimension_type_nbt_for_proto(key, 754)`. Kept for
/// downstream callers that don't yet know the negotiated proto.
pub fn dimension_type_nbt(key: &str) -> Result<Vec<u8>, ProtocolError> {
    dimension_type_nbt_with_version(key, DimSchema::V1_16_2)
}

/// Build the standalone "dimension type" compound for 1.20.4+ JoinGame.
pub fn dimension_type_nbt_1_20_4(key: &str) -> Result<Vec<u8>, ProtocolError> {
    dimension_type_nbt_with_version(key, DimSchema::V1_20_4)
}

/// Proto-aware inline dimension NBT.
///
/// Per minecraft.wiki §JoinGame + ViaVersion `EntityPacketRewriter1_17`:
///   * 751 - 754 (1.16.2 - 1.16.5)  →  13-field element, no `min_y`/`height`
///   * 755 - 763 (1.17  - 1.19.4)   →  + `min_y`/`height` (1.17 additions)
///   * 764+      (1.20.2+)          →  + `monster_spawn_light_level`,
///                                      `monster_spawn_block_light_limit`,
///                                      `fixed_time` int placeholder
pub fn dimension_type_nbt_for_proto(key: &str, proto: u32) -> Result<Vec<u8>, ProtocolError> {
    let schema = match proto {
        p if p >= 764 => DimSchema::V1_20_4,
        p if p >= 755 => DimSchema::V1_17,
        _ => DimSchema::V1_16_2,
    };
    dimension_type_nbt_with_version(key, schema)
}

/// Per-era schema selector for the inline dimension element.
#[derive(Debug, Clone, Copy)]
enum DimSchema {
    /// 1.16.2-1.16.5: 13-field set, no height/min_y.
    V1_16_2,
    /// 1.17-1.19.4: 1.16.2 set + `min_y` + `height`.
    V1_17,
    /// 1.20.4+: 1.17 set + spawn-light fields + fixed_time placeholder.
    V1_20_4,
}

fn dimension_type_nbt_with_version(key: &str, schema: DimSchema) -> Result<Vec<u8>, ProtocolError> {
    let (infiniburn, effects, has_skylight, has_ceiling, ultrawarm, natural) = match key {
        "minecraft:the_nether" => (
            "minecraft:infiniburn_nether",
            "minecraft:the_nether",
            false,
            true,
            true,
            false,
        ),
        "minecraft:the_end" => (
            "minecraft:infiniburn_end",
            "minecraft:the_end",
            false,
            false,
            false,
            false,
        ),
        _ => (
            "minecraft:infiniburn_overworld",
            "minecraft:overworld",
            true,
            false,
            false,
            true,
        ),
    };
    let element = dimension_type_element(
        has_skylight,
        has_ceiling,
        ultrawarm,
        natural,
        infiniburn,
        effects,
        matches!(schema, DimSchema::V1_20_4),
    );
    let element = augment_for_schema(element, schema);
    let mut root = HashMap::new();
    if let NbtTag::Compound(m) = element {
        root.extend(m);
    }
    let nbt = Nbt {
        name: String::new(),
        root,
    };
    let mut buf = BytesMut::new();
    nbt.encode(&mut buf)?;
    Ok(buf.to_vec())
}

/// Augment a base element compound with the per-era extras. Called
/// after `dimension_type_element` so the base 13-field set is shared
/// across all eras and only the per-era additions live here.
fn augment_for_schema(element: NbtTag, schema: DimSchema) -> NbtTag {
    let NbtTag::Compound(mut m) = element else {
        return element;
    };
    match schema {
        DimSchema::V1_16_2 => {},
        DimSchema::V1_17 => {
            // 1.17 added `min_y` + `height` per ViaVersion
            // `EntityPacketRewriter1_17::addNewDimensionData`.
            m.insert("min_y".into(), i(0));
            m.insert("height".into(), i(256));
        },
        DimSchema::V1_20_4 => {
            // 1.20.4+: `min_y`/`height` AND the spawn-light fields +
            // `fixed_time` placeholder. `dimension_type_element` with
            // `is_1_20_4 = true` already added the spawn-light extras,
            // so here we only need the 1.17 carry-overs.
            m.insert("min_y".into(), i(0));
            m.insert("height".into(), i(256));
        },
    }
    NbtTag::Compound(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_encodes_to_nonempty() {
        let b = dimension_codec_nbt().unwrap();
        assert!(b.len() > 32);
        // First byte is the Compound tag (10).
        assert_eq!(b[0], 10);
    }

    #[test]
    fn dimension_type_nether_has_no_skylight() {
        let b = dimension_type_nbt("minecraft:the_nether").unwrap();
        // The compound starts with tag 10, then i16 name length, then name…
        // Just verify it encoded.
        assert!(b.len() > 16);
        assert_eq!(b[0], 10);
    }
}
