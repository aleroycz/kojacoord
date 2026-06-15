//! Configuration-phase registry data for 1.20.5+ / 1.21 limbo.
//!
//! From 1.20.5 (proto 766) the client CLEARS its registries at the start
//! of the configuration phase and only repopulates them from either
//! (a) a negotiated "known pack" (the `SelectKnownPacks` handshake) or
//! (b) explicit `ClientboundRegistryData` packets. A limbo that sends
//! neither leaves the client with empty `dimension_type` / `worldgen/biome`
//! registries, so the JoinGame `dimension_type = VarInt(0)` reference
//! fails to resolve and the client disconnects. (1.20.2-1.20.4 differ:
//! they fall back to built-in defaults when registry data is absent,
//! which is why those protos survive the no-op config phase.)
//!
//! We send the full registry set ourselves, captured from PrismarineJS
//! `minecraft-data` `pc/<ver>/loginPacket.json` `dimensionCodec` and
//! converted to per-registry `ClientboundRegistryData` bodies by
//! `tools`/`gen_registries.py`. Each embedded bundle is:
//!
//! ```text
//! [u32 num_registries]
//! repeat num_registries:
//!   [u32 body_len][body]           // body = one RegistryData packet body
//! ```
//!
//! and each `body` is the wire payload of `ClientboundRegistryData`:
//!
//! ```text
//! [String registry_id]
//! [VarInt entry_count]
//! repeat entry_count:
//!   [String entry_key]
//!   [bool has_data]
//!   has_data ? [network NBT: nameless tag id + payload] : ()
//! ```
//!
//! The limbo prepends the proto-correct packet id and frames each body.

/// 1.20.5 / 1.20.6 (proto 766) — 8 registries.
static REGISTRIES_1_20_5: &[u8] =
    include_bytes!("../../../../crates/protocol/data/registries_1_20_5.bin");
/// 1.21 / 1.21.1 (proto 767) — 11 registries (adds painting_variant,
/// enchantment, jukebox_song).
static REGISTRIES_1_21: &[u8] =
    include_bytes!("../../../../crates/protocol/data/registries_1_21.bin");
/// 1.21.2 / 1.21.3 / 1.21.4 (proto 768/769) — 12 registries (adds
/// instrument). 1.21.4 added no synced registries over 1.21.3.
static REGISTRIES_1_21_3: &[u8] =
    include_bytes!("../../../../crates/protocol/data/registries_1_21_3.bin");
/// 1.21.5 (proto 770) — 18 registries: 1.21.3 set + the six mob-variant
/// registries 1.21.5 added (cat/chicken/cow/frog/pig/wolf_sound), per
/// ViaVersion `Protocol1_21_4To1_21_5`. Built by filtering the complete
/// 1.21.11 codec to that exact registry list.
static REGISTRIES_1_21_5: &[u8] =
    include_bytes!("../../../../crates/protocol/data/registries_1_21_5.bin");
/// 1.21.6 – 1.21.9 (proto 771/772/773) — 19 registries: 1.21.5 set +
/// `dialog` (added 1.21.6 per ViaVersion `Protocol1_21_5To1_21_6`).
/// 1.21.7/1.21.8/1.21.9 added no further synced registries.
static REGISTRIES_1_21_6: &[u8] =
    include_bytes!("../../../../crates/protocol/data/registries_1_21_6.bin");
/// 1.21.10 / 1.21.11 (proto 774) — full 23-registry set (adds
/// test_environment/test_instance/timeline/zombie_nautilus_variant),
/// captured verbatim from minecraft-data `pc/1.21.11`.
static REGISTRIES_1_21_11: &[u8] =
    include_bytes!("../../../../crates/protocol/data/registries_1_21_11.bin");

/// Selects the embedded registry bundle appropriate for a given Minecraft protocol version.
///
/// This returns a static byte slice containing the pre-generated configuration-phase
/// registry bundle for the requested protocol when the protocol uses per-registry
/// configuration (Minecraft 1.20.5 / 1.21.x series). For protocol numbers newer
/// than the newest supported bundle, the newest bundle is returned as a best-effort
/// fallback; for older protocols that do not use per-registry bundles this returns
/// `None`.
///
/// Mapping:
/// - 766 → 1.20.5 bundle
/// - 767 → 1.21.0 / 1.21.1 bundle
/// - 768..=769 → 1.21.2–1.21.4 bundle
/// - 770 → 1.21.5 bundle
/// - 771..=773 → 1.21.6–1.21.9 bundle
/// - 774 → 1.21.10 / 1.21.11 bundle
/// - p > 774 → newest bundle (best-effort fallback)
///
/// # Examples
///
/// ```ignore
/// assert!(bundle_for_proto(770).is_some()); // 1.21.5
/// assert!(bundle_for_proto(765).is_none()); // pre-1.20.5
/// assert!(bundle_for_proto(800).is_some()); // best-effort: newest embedded bundle
/// ```
pub fn bundle_for_proto(proto: u32) -> Option<&'static [u8]> {
    match proto {
        766 => Some(REGISTRIES_1_20_5),       // 1.20.5 / 1.20.6
        767 => Some(REGISTRIES_1_21),         // 1.21 / 1.21.1
        768..=769 => Some(REGISTRIES_1_21_3), // 1.21.2 / 1.21.3 / 1.21.4
        770 => Some(REGISTRIES_1_21_5),       // 1.21.5
        771..=773 => Some(REGISTRIES_1_21_6), // 1.21.6 – 1.21.9
        774 => Some(REGISTRIES_1_21_11),      // 1.21.10 / 1.21.11
        // Anything past the highest protocol we have data for reuses the
        // newest complete set as a logged best-effort.
        p if p > 774 => Some(REGISTRIES_1_21_11),
        _ => None,
    }
}

/// Indicates whether the registry bundle chosen for `proto` is a best-effort fallback.
///
/// Protocols greater than 774 reuse the newest-known embedded bundle as a best-effort mapping;
/// protocols 774 and below have version-matched bundles.
///
/// # Returns
///
/// `true` if the selection is a best-effort fallback (protocol > 774), `false` otherwise.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(bundle_is_fallback(774), false);
/// assert_eq!(bundle_is_fallback(775), true);
/// ```
pub fn bundle_is_fallback(proto: u32) -> bool {
    proto > 774
}

/// Split a registry bundle blob into its contained `ClientboundRegistryData` packet bodies.
///
/// The bundle format is: big-endian `u32` registry count, followed by that many entries each
/// encoded as a big-endian `u32` body length and then `body` bytes. This function returns
/// slices that borrow from the provided `bundle`.
///
/// On malformed input this returns an `Err` with one of the exact messages produced by the
/// parser:
/// - `"registry bundle truncated"` when a required u32 read would run past the end.
/// - `"registry bundle body overruns bundle"` when a declared body length extends beyond the bundle.
///
/// # Returns
///
/// `Ok(Vec<&[u8]>)` with one slice per registry-data body on success, `Err(String)` with a
/// descriptive message on malformed data.
///
/// # Examples
///
/// ```ignore
/// let mut bytes = Vec::new();
/// // num = 1
/// bytes.extend(&1u32.to_be_bytes());
/// // len = 3
/// bytes.extend(&3u32.to_be_bytes());
/// // body = [1,2,3]
/// bytes.extend(&[1u8, 2, 3]);
///
/// let parts = crate::net::registry_data::parse_bundle(&bytes).unwrap();
/// assert_eq!(parts.len(), 1);
/// assert_eq!(parts[0], &[1u8, 2, 3]);
/// ```
pub fn parse_bundle(bundle: &[u8]) -> Result<Vec<&[u8]>, String> {
    let mut off = 0usize;
    let read_u32 = |b: &[u8], off: &mut usize| -> Result<u32, String> {
        if *off + 4 > b.len() {
            return Err("registry bundle truncated".into());
        }
        let v = u32::from_be_bytes([b[*off], b[*off + 1], b[*off + 2], b[*off + 3]]);
        *off += 4;
        Ok(v)
    };
    let num = read_u32(bundle, &mut off)?;
    let mut out = Vec::with_capacity(num as usize);
    for _ in 0..num {
        let len = read_u32(bundle, &mut off)? as usize;
        if off + len > bundle.len() {
            return Err("registry bundle body overruns bundle".into());
        }
        out.push(&bundle[off..off + len]);
        off += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extracts registry identifier strings from a registry bundle.
    ///
    /// Parses the provided bundle framing and returns the list of registry IDs found in each embedded
    /// registry-data body. Each body is expected to start with a Minecraft string (VarInt length
    /// followed by UTF-8 bytes); this function decodes that leading string for every body.
    ///
    /// # Parameters
    ///
    /// - `bundle` — byte slice containing a registry bundle (u32 count, then repeated u32 body_len + body).
    ///
    /// # Returns
    ///
    /// A `Vec<String>` containing the registry id decoded from the start of each body, in bundle order.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let bundle: &[u8] = &[
    ///     0, 0, 0, 1,      // num_registries = 1
    ///     0, 0, 0, 5,      // body_len = 5
    ///     0x04, b't', b'e', b's', b't', // body: VarInt(4) + "test"
    /// ];
    /// let ids = registry_ids(bundle);
    /// assert_eq!(ids, vec!["test".to_string()]);
    /// ```
    fn registry_ids(bundle: &[u8]) -> Vec<String> {
        let bodies = parse_bundle(bundle).expect("parse");
        bodies
            .iter()
            .map(|b| {
                // body starts with a Minecraft String: VarInt len + utf8.
                let mut i = 0usize;
                let mut len = 0u32;
                let mut shift = 0;
                loop {
                    let byte = b[i];
                    i += 1;
                    len |= ((byte & 0x7F) as u32) << shift;
                    if byte & 0x80 == 0 {
                        break;
                    }
                    shift += 7;
                }
                String::from_utf8(b[i..i + len as usize].to_vec()).unwrap()
            })
            .collect()
    }

    #[test]
    fn bundles_parse_and_contain_core_registries() {
        // Per-version registry counts (ViaVersion-derived): 1.21.5 adds
        // 6 mob-variant registries, 1.21.6 adds dialog, 1.21.10/.11 add 4.
        for (proto, expect_n) in [
            (766u32, 8usize), // 1.20.5/.6
            (767, 11),        // 1.21/.1
            (768, 12),        // 1.21.2/.3
            (769, 12),        // 1.21.4 (no additions over 1.21.3)
            (770, 18),        // 1.21.5
            (771, 19),        // 1.21.6
            (772, 19),        // 1.21.7/.8
            (773, 19),        // 1.21.9
            (774, 23),        // 1.21.10/.11
        ] {
            let bundle = bundle_for_proto(proto).expect("bundle present");
            let ids = registry_ids(bundle);
            assert_eq!(ids.len(), expect_n, "proto {proto} registry count");
            // dimension_type + biome are always required to join a world.
            for required in ["minecraft:dimension_type", "minecraft:worldgen/biome"] {
                assert!(
                    ids.iter().any(|s| s == required),
                    "proto {proto} bundle missing {required}"
                );
            }
        }
        // 1.21.5+ must carry the new mob-variant registries.
        let ids = registry_ids(bundle_for_proto(770).unwrap());
        for v in [
            "minecraft:cat_variant",
            "minecraft:pig_variant",
            "minecraft:wolf_sound_variant",
        ] {
            assert!(ids.iter().any(|s| s == v), "1.21.5 missing {v}");
        }
        // dialog only from 1.21.6.
        assert!(!registry_ids(bundle_for_proto(770).unwrap())
            .iter()
            .any(|s| s == "minecraft:dialog"));
        assert!(registry_ids(bundle_for_proto(771).unwrap())
            .iter()
            .any(|s| s == "minecraft:dialog"));
    }

    #[test]
    fn fallback_mapping() {
        // Every protocol through 774 has a version-matched set.
        for p in 766..=774 {
            assert!(bundle_for_proto(p).is_some(), "proto {p} bundle");
            assert!(!bundle_is_fallback(p), "proto {p} should be exact");
        }
        // Only future/unknown protocols are best-effort.
        assert!(bundle_for_proto(775).is_some());
        assert!(bundle_is_fallback(775));
        assert!(bundle_for_proto(765).is_none());
    }
}
