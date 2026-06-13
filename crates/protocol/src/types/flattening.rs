//! Block and item flattening tables for the 1.13 flattening update.
//!
//! Minecraft 1.13 (The Update Aquatic) changed from numeric block/item IDs
//! to varint state IDs. This module provides bidirectional mapping between
//! legacy (pre-1.13) IDs and modern (1.13+) state IDs.
//!
//! ## Data source
//!
//! The mappings live in TOML files under `crates/protocol/data/`:
//!   - `block_flattening.toml` — `[legacy_id, meta, modern_state_id, name?]`
//!   - `item_flattening.toml` — `[legacy_id, modern_id, name?]` plus an
//!     optional `identity_range = [start, end]` for the bulk of items
//!     whose ids didn't change.
//!
//! The TOML files are baked into the binary at compile time via
//! `include_str!`, so there's no runtime filesystem access. Parsing is
//! done once on first table construction and cached in a `OnceLock`.
//!
//! Regenerate the TOML from upstream data with:
//!
//! ```ignore
//! cargo run -p kojacoord-protocol --bin gen_flattening
//! ```

use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;

const BLOCK_TOML: &str = include_str!("../../data/block_flattening.toml");
const ITEM_TOML: &str = include_str!("../../data/item_flattening.toml");

/// Legacy block state: `(block_id << 4) | meta`.
pub type LegacyBlockState = u32;
/// Modern block state ID (varint on the wire).
pub type ModernBlockState = u32;
/// Legacy item ID (numeric, 16-bit).
pub type LegacyItemId = i16;
/// Modern item ID (varint on the wire).
pub type ModernItemId = u32;

// ── TOML schema ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct BlockFile {
    blocks: Vec<BlockRow>,
}

/// Either `[legacy_id, meta, modern]` or `[legacy_id, meta, modern, name]`.
#[derive(Deserialize)]
#[serde(untagged)]
enum BlockRow {
    Anonymous(u32, u32, u32),
    Named(u32, u32, u32, String),
}

impl BlockRow {
    fn legacy_state(&self) -> LegacyBlockState {
        let (id, meta) = match self {
            BlockRow::Anonymous(id, meta, _) => (*id, *meta),
            BlockRow::Named(id, meta, _, _) => (*id, *meta),
        };
        debug_assert!(
            meta < 16,
            "flattening: meta must fit in 4 bits, got {meta} for block {id}"
        );
        (id << 4) | (meta & 0xF)
    }

    fn modern(&self) -> ModernBlockState {
        match self {
            BlockRow::Anonymous(_, _, m) => *m,
            BlockRow::Named(_, _, m, _) => *m,
        }
    }

    fn name(&self) -> Option<&str> {
        match self {
            BlockRow::Anonymous(..) => None,
            BlockRow::Named(_, _, _, n) => Some(n.as_str()),
        }
    }
}

#[derive(Deserialize)]
struct ItemFile {
    #[serde(default)]
    identity_range: Option<[i32; 2]>,
    #[serde(default)]
    items: Vec<ItemRow>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ItemRow {
    Anonymous(i16, u32),
    Named(i16, u32, String),
}

impl ItemRow {
    fn legacy(&self) -> LegacyItemId {
        match self {
            ItemRow::Anonymous(l, _) => *l,
            ItemRow::Named(l, _, _) => *l,
        }
    }
    fn modern(&self) -> ModernItemId {
        match self {
            ItemRow::Anonymous(_, m) => *m,
            ItemRow::Named(_, m, _) => *m,
        }
    }

    fn name(&self) -> Option<&str> {
        match self {
            ItemRow::Anonymous(..) => None,
            ItemRow::Named(_, _, n) => Some(n.as_str()),
        }
    }
}

// ── Tables ───────────────────────────────────────────────────────────────

pub struct BlockFlatteningTable {
    legacy_to_modern: &'static HashMap<LegacyBlockState, ModernBlockState>,
    modern_to_legacy: &'static HashMap<ModernBlockState, LegacyBlockState>,
    names: &'static HashMap<LegacyBlockState, &'static str>,
}

pub struct ItemFlatteningTable {
    legacy_to_modern: &'static HashMap<LegacyItemId, ModernItemId>,
    modern_to_legacy: &'static HashMap<ModernItemId, LegacyItemId>,
    names: &'static HashMap<LegacyItemId, &'static str>,
}

/// Cached parsed tables. Built once on first access; the TOML parse and
/// HashMap construction cost is paid exactly once per process.
struct ParsedTables {
    blocks_l2m: HashMap<LegacyBlockState, ModernBlockState>,
    blocks_m2l: HashMap<ModernBlockState, LegacyBlockState>,
    /// Human-readable name per legacy state, sourced from the optional
    /// 4th element of each block row. Used by [`BlockFlatteningTable::name`]
    /// for diagnostics; empty when the TOML row omits the name.
    block_names: HashMap<LegacyBlockState, &'static str>,
    items_l2m: HashMap<LegacyItemId, ModernItemId>,
    items_m2l: HashMap<ModernItemId, LegacyItemId>,
    item_names: HashMap<LegacyItemId, &'static str>,
}

static PARSED: Lazy<ParsedTables> = Lazy::new(|| {
    let blocks: BlockFile = toml::from_str(BLOCK_TOML)
        .expect("block_flattening.toml failed to parse — regenerate via `gen_flattening`");
    let items: ItemFile = toml::from_str(ITEM_TOML)
        .expect("item_flattening.toml failed to parse — regenerate via `gen_flattening`");

    let mut blocks_l2m = HashMap::with_capacity(blocks.blocks.len());
    let mut blocks_m2l = HashMap::with_capacity(blocks.blocks.len());
    let mut block_names: HashMap<LegacyBlockState, &'static str> = HashMap::new();
    for row in &blocks.blocks {
        let legacy = row.legacy_state();
        let modern = row.modern();
        blocks_l2m.insert(legacy, modern);
        // First writer wins for the inverse — multiple legacy states can
        // collapse to one modern state, but only the first declaration in
        // the TOML round-trips. The TOML ordering documents which is
        // canonical.
        blocks_m2l.entry(modern).or_insert(legacy);
        if let Some(name) = row.name() {
            // Leak each name to get a `'static str`. The set is bounded by
            // the TOML file size (~hundreds of entries) so the leak is
            // both small and one-shot at startup.
            block_names.insert(legacy, Box::leak(name.to_owned().into_boxed_str()));
        }
    }

    let mut items_l2m = HashMap::new();
    let mut items_m2l = HashMap::new();
    let mut item_names: HashMap<LegacyItemId, &'static str> = HashMap::new();
    if let Some([start, end]) = items.identity_range {
        for i in start..=end {
            if i < i16::MIN as i32 || i > i16::MAX as i32 {
                continue;
            }
            let l = i as i16;
            let m = i as u32;
            items_l2m.insert(l, m);
            items_m2l.insert(m, l);
        }
    }
    for row in &items.items {
        items_l2m.insert(row.legacy(), row.modern());
        items_m2l.entry(row.modern()).or_insert(row.legacy());
        if let Some(name) = row.name() {
            item_names.insert(row.legacy(), Box::leak(name.to_owned().into_boxed_str()));
        }
    }

    ParsedTables {
        blocks_l2m,
        blocks_m2l,
        block_names,
        items_l2m,
        items_m2l,
        item_names,
    }
});

impl BlockFlatteningTable {
    /// Build a table view backed by the process-wide parsed data. Cheap
    /// (no map cloning): just hands out static references.
    pub fn new() -> Self {
        Self {
            legacy_to_modern: &PARSED.blocks_l2m,
            modern_to_legacy: &PARSED.blocks_m2l,
            names: &PARSED.block_names,
        }
    }

    pub fn legacy_to_modern(&self, legacy: LegacyBlockState) -> Option<ModernBlockState> {
        self.legacy_to_modern.get(&legacy).copied()
    }

    pub fn modern_to_legacy(&self, modern: ModernBlockState) -> Option<LegacyBlockState> {
        self.modern_to_legacy.get(&modern).copied()
    }

    /// Human-readable name from the TOML for the given legacy state, if
    /// any. Used by the converter trace logs and by debugging tools.
    pub fn name(&self, legacy: LegacyBlockState) -> Option<&'static str> {
        self.names.get(&legacy).copied()
    }

    /// Total number of legacy→modern entries loaded from TOML. Useful for
    /// sanity-checking after a regenerate.
    pub fn len(&self) -> usize {
        self.legacy_to_modern.len()
    }

    pub fn is_empty(&self) -> bool {
        self.legacy_to_modern.is_empty()
    }
}

impl Default for BlockFlatteningTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ItemFlatteningTable {
    pub fn new() -> Self {
        Self {
            legacy_to_modern: &PARSED.items_l2m,
            modern_to_legacy: &PARSED.items_m2l,
            names: &PARSED.item_names,
        }
    }

    pub fn legacy_to_modern(&self, legacy: LegacyItemId) -> Option<ModernItemId> {
        self.legacy_to_modern.get(&legacy).copied()
    }

    pub fn modern_to_legacy(&self, modern: ModernItemId) -> Option<LegacyItemId> {
        self.modern_to_legacy.get(&modern).copied()
    }

    pub fn name(&self, legacy: LegacyItemId) -> Option<&'static str> {
        self.names.get(&legacy).copied()
    }

    pub fn len(&self) -> usize {
        self.legacy_to_modern.len()
    }

    pub fn is_empty(&self) -> bool {
        self.legacy_to_modern.is_empty()
    }
}

impl Default for ItemFlatteningTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_at_least_air_and_stone() {
        let blocks = BlockFlatteningTable::new();
        assert_eq!(blocks.legacy_to_modern(0), Some(0));
        // Stone, legacy (1, 0).
        assert_eq!(blocks.legacy_to_modern(1 << 4), Some(1));
    }

    #[test]
    fn block_table_non_empty() {
        let blocks = BlockFlatteningTable::new();
        // Sanity: TOML should load at least the air entry. Real data has
        // hundreds; this guards against the loader silently producing an
        // empty map.
        assert!(!blocks.is_empty());
    }

    #[test]
    fn item_table_has_known_mappings() {
        let items = ItemFlatteningTable::new();
        // Stone is legacy id 1 → modern id 1 in the generated table.
        assert_eq!(items.legacy_to_modern(1), Some(1));
        // Sanity: the inverse map agrees on at least one entry.
        if let Some(modern) = items.legacy_to_modern(1) {
            assert_eq!(items.modern_to_legacy(modern), Some(1));
        }
        // Table should not be trivially empty after the generator runs.
        assert!(
            items.len() > 50,
            "expected >50 item mappings, got {}",
            items.len()
        );
    }

    #[test]
    fn meta_is_bounded_to_4_bits() {
        // Sanity: every entry must have meta < 16, otherwise the
        // `(id << 4) | meta` packing would corrupt the block id field.
        // (Caught by debug_assert! in `BlockRow::legacy_state`.)
        let _ = BlockFlatteningTable::new();
    }
}
