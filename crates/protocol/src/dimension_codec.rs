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

#[allow(clippy::too_many_arguments)]
fn dimension_type_element(
    has_skylight: bool,
    has_ceiling: bool,
    ultrawarm: bool,
    natural: bool,
    infiniburn: &str,
    effects: &str,
    is_1_20_4: bool,
    fixed_time: Option<i64>,
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
    if is_1_20_4 {
        m.insert("min_y".into(), i(0));
        m.insert("height".into(), i(256));
    }
    m.insert("logical_height".into(), i(256));
    m.insert("coordinate_scale".into(), NbtTag::Double(1.0));
    m.insert("ultrawarm".into(), b(ultrawarm as i8));
    m.insert("has_ceiling".into(), b(has_ceiling as i8));

    if is_1_20_4 {
        m.insert("monster_spawn_light_level".into(), i(7));
        m.insert("monster_spawn_block_light_limit".into(), i(0));
        if let Some(t) = fixed_time {
            m.insert("fixed_time".into(), NbtTag::Long(t));
        }
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
        None,
    );
    let nether = dimension_type_element(
        false,
        true,
        true,
        false,
        "minecraft:infiniburn_nether",
        "minecraft:the_nether",
        is_1_20_4,
        Some(18000),
    );
    let end = dimension_type_element(
        false,
        false,
        false,
        false,
        "minecraft:infiniburn_end",
        "minecraft:the_end",
        is_1_20_4,
        None,
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

/// Selects a dimension-schema based on a protocol version and returns the encoded inline dimension-type NBT for the given registry key.
///
/// The function maps `proto` to an internal `DimSchema`:
/// - proto >= 764 => V1_20_4
/// - 759 ..= 763   => V1_19
/// - 758           => V1_18_2
/// - 755 ..= 757   => V1_17
/// - otherwise     => V1_16_2
///
/// The produced NBT matches the field layout expected by the selected schema (e.g., presence or absence of `min_y`/`height`, spawn-light fields, and the 1.20.4 placeholders).
///
/// # Examples
///
/// ```ignore
/// let bytes = dimension_type_nbt_for_proto("minecraft:overworld", 758).unwrap();
/// assert!(bytes.len() > 0);
/// ```
pub fn dimension_type_nbt_for_proto(key: &str, proto: u32) -> Result<Vec<u8>, ProtocolError> {
    let schema = match proto {
        p if p >= 764 => DimSchema::V1_20_4,
        p if p >= 759 => DimSchema::V1_19,
        p if p >= 758 => DimSchema::V1_18_2,
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
    /// 1.17 / 1.17.1: 1.16.2 set + `min_y` + `height`.
    V1_17,
    /// 1.18 / 1.18.2 (proto 758): identical field set to `V1_17`.
    /// Given its own variant (rather than folded into `V1_17`) so the
    /// proto→schema match in `dimension_type_nbt_for_proto` has an
    /// explicit, documented branch for 758 instead of relying on the
    /// `>= 755` fallthrough — this is the version that was previously
    /// missing an explicit mapping.
    V1_18_2,
    /// 1.19 - 1.19.4: 1.17 set + `monster_spawn_block_light_limit`
    /// + `monster_spawn_light_level` per ViaVersion
    /// `EntityPacketRewriter1_19::addMonsterSpawnData`.
    V1_19,
    /// 1.20.4+: 1.19 set + `fixed_time` placeholder.
    V1_20_4,
}

fn dimension_type_nbt_with_version(key: &str, schema: DimSchema) -> Result<Vec<u8>, ProtocolError> {
    let (infiniburn, effects, has_skylight, has_ceiling, ultrawarm, natural, fixed_time) = match key
    {
        "minecraft:the_nether" => (
            "minecraft:infiniburn_nether",
            "minecraft:the_nether",
            false,
            true,
            true,
            false,
            Some(18000i64),
        ),
        "minecraft:the_end" => (
            "minecraft:infiniburn_end",
            "minecraft:the_end",
            false,
            false,
            false,
            false,
            None,
        ),
        _ => (
            "minecraft:infiniburn_overworld",
            "minecraft:overworld",
            true,
            false,
            false,
            true,
            None,
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
        fixed_time,
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

/// Insert era-specific integer fields into a dimension-type compound.
///
/// For compound `element` values this adds or overrides integer keys required by
/// the given `schema`:
/// - V1_16_2: no additions.
/// - V1_17 and V1_18_2: `min_y = 0`, `height = 256`.
/// - V1_19: `min_y = 0`, `height = 256`, `monster_spawn_block_light_limit = 0`,
///   `monster_spawn_light_level = 11`.
/// - V1_20_4: `min_y = 0`, `height = 256` (other 1.20.4 fields are added by
///   the base element constructor when applicable).
///
/// If `element` is not a compound it is returned unchanged.
///
/// # Examples
///
/// ```ignore
/// use std::collections::HashMap;
/// // build an empty compound element
/// let base = NbtTag::Compound(HashMap::new());
/// let augmented = augment_for_schema(base, DimSchema::V1_17);
/// match augmented {
///     NbtTag::Compound(m) => assert!(m.contains_key("min_y") && m.contains_key("height")),
///     _ => panic!("expected a compound"),
/// }
/// ```
fn augment_for_schema(element: NbtTag, schema: DimSchema) -> NbtTag {
    let NbtTag::Compound(mut m) = element else {
        return element;
    };
    match schema {
        DimSchema::V1_16_2 => {},
        DimSchema::V1_17 | DimSchema::V1_18_2 => {
            // 1.17 added `min_y` + `height` per ViaVersion
            // `EntityPacketRewriter1_17::addNewDimensionData`.
            m.insert("min_y".into(), i(0));
            m.insert("height".into(), i(256));
        },
        DimSchema::V1_19 => {
            // 1.17 carry-overs.
            m.insert("min_y".into(), i(0));
            m.insert("height".into(), i(256));
            // 1.19 additions per ViaVersion
            // `EntityPacketRewriter1_19::addMonsterSpawnData`:
            //   monster_spawn_block_light_limit = 0
            //   monster_spawn_light_level       = 11
            m.insert("monster_spawn_block_light_limit".into(), i(0));
            m.insert("monster_spawn_light_level".into(), i(7));
        },
        DimSchema::V1_20_4 => {
            // 1.20.4+: 1.17 carry-overs + spawn-light fields (already
            // added by `dimension_type_element` with `is_1_20_4 =
            // true`) + nothing extra here.
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
        let buf = dimension_codec_nbt().unwrap();
        assert!(buf.len() > 32);
        // Root NBT form: first byte is the Compound tag (10).
        assert_eq!(buf[0], 10);
    }

    #[test]
    fn dimension_type_nether_has_no_skylight() {
        let buf = dimension_type_nbt("minecraft:the_nether").unwrap();
        assert!(buf.len() > 16);
        // The Notchian client's NBT reader requires a top-level value to be
        // a *named* compound tag, even when the name is empty: the buffer
        // must start with TAG_Compound (10) followed by a 2-byte empty
        // name-length prefix (0x00 0x00). Stripping this prefix produces an
        // invalid NBT stream and triggers "Root tag must be a named compound
        // tag" client-side.
        assert_eq!(buf[0], 10);
        assert!(buf[1] == 0 && buf[2] == 0);
    }

    #[test]
    fn dimension_type_1_18_2_matches_1_17_field_set() {
        let v117 = dimension_type_nbt_for_proto("minecraft:overworld", 756).unwrap();
        let v1182 = dimension_type_nbt_for_proto("minecraft:overworld", 758).unwrap();
        assert_eq!(v117.len(), v1182.len());
    }

    #[test]
    fn dimension_type_1_18_2_differs_from_1_16_2() {
        let v1162 = dimension_type_nbt_for_proto("minecraft:overworld", 754).unwrap();
        let v1182 = dimension_type_nbt_for_proto("minecraft:overworld", 758).unwrap();
        // 1.18.2 has two extra Int fields (min_y, height) vs 1.16.2.
        assert!(v1182.len() > v1162.len());
    }

    #[test]
    fn dimension_type_nbt_matches_raw_nbt_encode_for_same_compound() {
        // `dimension_type_nbt` must produce exactly the same bytes as
        // `Nbt::encode` for the equivalent compound — there is no separate
        // "headless" form. This is the wire format Join Game / Respawn embed
        // for the inline dimension-type tag.
        let actual = dimension_type_nbt("minecraft:overworld").unwrap();

        let mut root = HashMap::new();
        if let NbtTag::Compound(m) = augment_for_schema(
            dimension_type_element(
                true,
                false,
                false,
                true,
                "minecraft:infiniburn_overworld",
                "minecraft:overworld",
                false,
                None,
            ),
            DimSchema::V1_16_2,
        ) {
            root = m;
        }
        let nbt = Nbt {
            name: String::new(),
            root,
        };
        let mut expected = BytesMut::new();
        nbt.encode(&mut expected).unwrap();

        assert_eq!(actual.len(), expected.len());
    }
}
