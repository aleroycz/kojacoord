//! Shared slot/item conversion helpers for cross-version converters.
//!
//! The 1.13 flattening replaced legacy `(item_id: i16, damage: i16)`
//! pairs with a single varint item id and dropped the damage field.
//! The 1.20.5 slot rework added a state-id varint prefix for
//! change-tracking. Each converter that touches `SetSlot`,
//! `WindowItems`, or `EntityEquipment` calls into the helpers here so
//! the mapping logic stays in one place — keep new wire-shape changes
//! adding cases to [`SlotLayout`] rather than open-coding them at the
//! call site.

use bytes::{Buf, BufMut, BytesMut};
use kojacoord_protocol::codec::{Decode, Encode};
use kojacoord_protocol::types::slot::Slot;

pub use kojacoord_protocol::types::slot::{LegacySlot, LegacySlotData};
use kojacoord_protocol::types::VarInt;
use kojacoord_protocol::{ItemFlatteningTable, ProtocolVersion};

pub fn is_legacy_slot(ver: ProtocolVersion) -> bool {
    matches!(
        ver,
        ProtocolVersion::V1_6_4
            | ProtocolVersion::V1_7_10
            | ProtocolVersion::V1_8
            | ProtocolVersion::V1_12_2
    )
}

pub fn modern_slot_parsable(ver: ProtocolVersion) -> bool {
    matches!(ver, ProtocolVersion::V1_16_5 | ProtocolVersion::V1_19_4)
}

pub fn has_state_id(ver: ProtocolVersion) -> bool {
    matches!(
        ver,
        ProtocolVersion::V1_19_4 | ProtocolVersion::V1_20_4 | ProtocolVersion::V1_21
    )
}

/// Coarse classification of the slot wire format for a given protocol —
/// the converter dispatch logs this at trace level so packet-flow dumps
/// show which slot decoder ought to be in use.
#[derive(Debug, Clone, Copy)]
pub enum SlotLayout {
    /// Pre-1.13 legacy slot: short item id + byte count + short damage + optional NBT.
    Legacy,
    /// 1.13 – 1.19.3: varint item id + byte count + optional NBT.
    Modern,
    /// 1.19.4 – 1.20.x: prefixed with a state-id varint for change tracking.
    ModernWithStateId,
    Unknown,
}

pub fn slot_layout(ver: ProtocolVersion) -> SlotLayout {
    if is_legacy_slot(ver) {
        SlotLayout::Legacy
    } else if has_state_id(ver) {
        SlotLayout::ModernWithStateId
    } else if modern_slot_parsable(ver) {
        SlotLayout::Modern
    } else {
        SlotLayout::Unknown
    }
}

/// Downgrade a 1.13+ slot into the pre-1.13 wire shape. Looks the
/// item id up in [`ItemFlatteningTable`]; unknown items are
/// truncated to 16-bit (with a warning) rather than dropped, because
/// dropping the slot would desync the client's inventory model.
pub fn modern_slot_to_legacy(slot: &Slot) -> LegacySlot {
    let flattening = ItemFlatteningTable::new();
    match &slot.0 {
        None => LegacySlot(None),
        Some(d) => {
            // Map modern item_id to legacy item_id using flattening table
            let legacy_item_id = match flattening.modern_to_legacy(d.item_id as u32) {
                Some(id) => id,
                None => {
                    // Fallback: truncate to legacy ID range if no mapping found
                    tracing::warn!(
                        modern_id = d.item_id,
                        "No mapping for modern item ID, using fallback"
                    );
                    (d.item_id & 0xFFFF) as i16
                },
            };
            LegacySlot(Some(LegacySlotData {
                item_id: legacy_item_id,
                count: d.count,
                damage: 0, // Legacy uses damage, modern doesn't
                nbt: d.nbt.clone(),
            }))
        },
    }
}

/// Inverse of [`modern_slot_to_legacy`]. The `damage` field is
/// dropped during conversion — 1.13+ encodes durability via NBT, and
/// the proxy doesn't fabricate that. Damage-discriminated items
/// (potions, dyes, …) round-trip as their base item only.
pub fn legacy_slot_to_modern(slot: &LegacySlot) -> Slot {
    let flattening = ItemFlatteningTable::new();
    match &slot.0 {
        None => Slot(None),
        Some(d) => {
            // Map legacy item_id to modern item_id using flattening table
            let modern_item_id = match flattening.legacy_to_modern(d.item_id) {
                Some(id) => id,
                None => {
                    // Fallback: use legacy ID as-is if no mapping found
                    tracing::warn!(
                        legacy_id = d.item_id,
                        "No mapping for legacy item ID, using fallback"
                    );
                    d.item_id as u32
                },
            };
            Slot(Some(kojacoord_protocol::types::slot::SlotData {
                item_id: modern_item_id as i32,
                count: d.count,
                nbt: d.nbt.clone(),
            }))
        },
    }
}

/// EntityEquipment slot indices: 1.9+ added off-hand at index 1 and
/// shifted armour up. `None` means the modern slot has no legacy
/// equivalent (off-hand items just vanish on the way down).
pub fn map_equipment_slot(modern_idx: u8) -> Option<i16> {
    match modern_idx {
        0 => Some(0), // Main hand
        1 => None,    // Off hand (not present in legacy)
        2 => Some(1), // Boots
        3 => Some(2), // Leggings
        4 => Some(3), // Chestplate
        5 => Some(4), // Helmet
        _ => None,
    }
}

/// Inverse of [`map_equipment_slot`]; never returns the off-hand
/// (index 1) since legacy never had one to begin with.
pub fn map_legacy_equipment_slot(legacy_idx: i16) -> Option<u8> {
    match legacy_idx {
        0 => Some(0), // Main hand
        1 => Some(2), // Boots
        2 => Some(3), // Leggings
        3 => Some(4), // Chestplate
        4 => Some(5), // Helmet
        _ => None,
    }
}

/// Rewrite a legacy `SetSlot` body in-place into the 1.13+ wire shape.
/// Reads the legacy fields (window id + slot index + optional slot
/// payload) and writes the modern equivalent over `body`. Errors
/// surface as `String` because the upstream callers in the converters
/// don't share an error type.
pub fn convert_set_slot_legacy_to_modern(body: &mut BytesMut) -> Result<(), String> {
    let window_id = body.get_u8();
    let slot = body.get_i16();

    // Read legacy slot
    let has_item = body.get_u8() != 0;
    let legacy_slot = if has_item {
        let item_id = body.get_i16();
        let count = body.get_u8();
        let damage = body.get_i16();
        let nbt_len = VarInt::decode(&mut body.clone().freeze())
            .map_err(|e| e.to_string())?
            .0;
        let nbt = if nbt_len > 0 {
            let nbt_bytes = body.split_to(nbt_len as usize).to_vec();
            Some(
                kojacoord_protocol::types::Nbt::decode(&mut bytes::Bytes::copy_from_slice(
                    &nbt_bytes,
                ))
                .unwrap_or_else(|_| kojacoord_protocol::types::Nbt::empty("")),
            )
        } else {
            None
        };
        LegacySlot(Some(LegacySlotData {
            item_id,
            count: count as i8,
            damage,
            nbt,
        }))
    } else {
        LegacySlot(None)
    };

    // Convert to modern slot
    let modern_slot = legacy_slot_to_modern(&legacy_slot);

    // Rebuild body in modern format
    body.clear();
    body.put_u8(window_id);
    body.put_i16(slot);
    modern_slot.encode(body).map_err(|e| e.to_string())?;

    Ok(())
}

/// Reverse of [`convert_set_slot_legacy_to_modern`]: rewrite a modern
/// `SetSlot` body into the legacy shape so a pre-1.13 backend can
/// parse what a 1.13+ client sent.
#[allow(dead_code)]
pub fn convert_set_slot_modern_to_legacy(body: &mut BytesMut) -> Result<(), String> {
    let window_id = body.get_u8();
    let slot = body.get_i16();

    // Read modern slot
    let modern_slot = Slot::decode(&mut body.clone().freeze()).map_err(|e| e.to_string())?;

    // Convert to legacy slot
    let legacy_slot = modern_slot_to_legacy(&modern_slot);

    // Rebuild body in legacy format
    body.clear();
    body.put_u8(window_id);
    body.put_i16(slot);
    match legacy_slot.0 {
        None => body.put_i16(-1),
        Some(data) => {
            body.put_i16(data.item_id);
            body.put_i8(data.count);
            body.put_i16(data.damage);
            match &data.nbt {
                None => VarInt(0).encode(body).map_err(|e| e.to_string())?,
                Some(nbt) => {
                    nbt.encode(body).map_err(|e| e.to_string())?;
                },
            }
        },
    }

    Ok(())
}
