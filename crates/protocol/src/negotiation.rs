//! Protocol version table and "nearest known version" resolution.
//!
//! Source: <https://minecraft.wiki/w/Protocol_version> — every release where the
//! Java Edition protocol number changed. Each `ProtocolVersion` variant here
//! corresponds to one of those bumps; older subversions that did not bump the
//! protocol ID share the same variant as their preceding release.
//!
//! `Epoch` groups protocol versions that are close enough that one converter
//! implementation can reasonably handle the whole range. Converter dispatch is
//! keyed off `(src_epoch, dst_epoch)` rather than exact version pairs.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolVersion {
    // Pre-netty (raw TCP, completely different protocol shape).
    V1_6_1, // 73 (pre-netty)
    V1_6_2, // 74 (pre-netty)
    V1_6_4, // 78 (pre-netty; also covers 1.6.3 which never shipped a different proto)

    // 1.7.x family — first netty release.
    V1_7_2,  // 4
    V1_7_6,  // 5  (also 1.7.10)
    V1_7_10, // 5  alias

    // 1.8.x family — single bump.
    V1_8, // 47

    // 1.9.x family.
    V1_9,   // 107
    V1_9_1, // 108
    V1_9_2, // 109
    V1_9_4, // 110

    // 1.10.x family.
    V1_10, // 210

    // 1.11.x family.
    V1_11,   // 315
    V1_11_1, // 316  (also 1.11.2)

    // 1.12.x family — current "fully supported" reference.
    V1_12,   // 335
    V1_12_1, // 338
    V1_12_2, // 340

    // 1.13.x family — the "flattening" boundary (blocks/items get new IDs).
    V1_13,   // 393
    V1_13_1, // 401
    V1_13_2, // 404

    // 1.14.x family — villages & pillage.
    V1_14,   // 477
    V1_14_1, // 480
    V1_14_2, // 485
    V1_14_3, // 490
    V1_14_4, // 498

    // 1.15.x family — buzzy bees.
    V1_15,   // 573
    V1_15_1, // 575
    V1_15_2, // 578

    // 1.16.x family — nether update.
    V1_16,   // 735
    V1_16_1, // 736
    V1_16_2, // 751
    V1_16_3, // 753
    V1_16_4, // 754  (also 1.16.5)
    V1_16_5, // 754  alias

    // 1.17.x family — caves & cliffs part 1, new world height.
    V1_17,   // 755
    V1_17_1, // 756

    // 1.18.x family — caves & cliffs part 2.
    V1_18,   // 757  (also 1.18.1)
    V1_18_2, // 758

    // 1.19.x family — wild update, chat signing.
    V1_19,   // 759
    V1_19_1, // 760  (also 1.19.2)
    V1_19_3, // 761
    V1_19_4, // 762

    // 1.20.x family — trails & tales; configuration phase introduced in 1.20.2.
    V1_20,   // 763  (also 1.20.1)
    V1_20_2, // 764
    V1_20_4, // 765  (also 1.20.4)
    V1_20_6, // 766  (also 1.20.6)

    // 1.21.x family — tricky trials; registry data packet rework.
    V1_21,    // 767  (also 1.21.1)
    V1_21_2,  // 768  (also 1.21.3)
    V1_21_4,  // 769
    V1_21_5,  // 770
    V1_21_6,  // 771
    V1_21_8,  // 772
    V1_21_9,  // 773
    V1_21_11, // 774

    Unknown(u32),
}

/// Coarse-grained version family used by the converter dispatch table. One
/// epoch boundary marks a protocol shape change big enough that we keep a
/// dedicated converter implementation between adjacent epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(non_camel_case_types)]
pub enum Epoch {
    /// Pre-netty (1.6.4 and earlier). Completely different framing.
    PreNetty,
    /// 1.7.x — first netty release.
    V1_7,
    /// 1.8.x — single bump.
    V1_8,
    /// 1.9 → 1.12.2 — packet IDs change but block/item palette is still numeric.
    V1_9_To_1_12,
    /// 1.13 → 1.15.2 — flattening, no biome storage rework yet.
    V1_13_To_1_15,
    /// 1.16 → 1.16.5 — nether update; dimension codec.
    V1_16,
    /// 1.17 → 1.18.2 — new world height + chunk encoding.
    V1_17_To_1_18,
    /// 1.19 → 1.19.4 — chat signing, profile keys.
    V1_19,
    /// 1.20 → 1.20.6 — configuration phase introduced.
    V1_20,
    /// 1.21+ — registry data packet rework.
    V1_21Plus,
    /// Used when we have no idea.
    Unknown,
}

impl ProtocolVersion {
    /// Map a wire protocol ID to the corresponding [`ProtocolVersion`].
    pub fn from_id(id: u32) -> Self {
        match id {
            73 => ProtocolVersion::V1_6_1,
            74 => ProtocolVersion::V1_6_2,
            78 => ProtocolVersion::V1_6_4,
            4 => ProtocolVersion::V1_7_2,
            5 => ProtocolVersion::V1_7_10,
            47 => ProtocolVersion::V1_8,
            107 => ProtocolVersion::V1_9,
            108 => ProtocolVersion::V1_9_1,
            109 => ProtocolVersion::V1_9_2,
            110 => ProtocolVersion::V1_9_4,
            210 => ProtocolVersion::V1_10,
            315 => ProtocolVersion::V1_11,
            316 => ProtocolVersion::V1_11_1,
            335 => ProtocolVersion::V1_12,
            338 => ProtocolVersion::V1_12_1,
            340 => ProtocolVersion::V1_12_2,
            393 => ProtocolVersion::V1_13,
            401 => ProtocolVersion::V1_13_1,
            404 => ProtocolVersion::V1_13_2,
            477 => ProtocolVersion::V1_14,
            480 => ProtocolVersion::V1_14_1,
            485 => ProtocolVersion::V1_14_2,
            490 => ProtocolVersion::V1_14_3,
            498 => ProtocolVersion::V1_14_4,
            573 => ProtocolVersion::V1_15,
            575 => ProtocolVersion::V1_15_1,
            578 => ProtocolVersion::V1_15_2,
            735 => ProtocolVersion::V1_16,
            736 => ProtocolVersion::V1_16_1,
            751 => ProtocolVersion::V1_16_2,
            753 => ProtocolVersion::V1_16_3,
            754 => ProtocolVersion::V1_16_5,
            755 => ProtocolVersion::V1_17,
            756 => ProtocolVersion::V1_17_1,
            757 => ProtocolVersion::V1_18,
            758 => ProtocolVersion::V1_18_2,
            759 => ProtocolVersion::V1_19,
            760 => ProtocolVersion::V1_19_1,
            761 => ProtocolVersion::V1_19_3,
            762 => ProtocolVersion::V1_19_4,
            763 => ProtocolVersion::V1_20,
            764 => ProtocolVersion::V1_20_2,
            765 => ProtocolVersion::V1_20_4,
            766 => ProtocolVersion::V1_20_6,
            767 => ProtocolVersion::V1_21,
            768 => ProtocolVersion::V1_21_2,
            769 => ProtocolVersion::V1_21_4,
            770 => ProtocolVersion::V1_21_5,
            771 => ProtocolVersion::V1_21_6,
            772 => ProtocolVersion::V1_21_8,
            773 => ProtocolVersion::V1_21_9,
            774 => ProtocolVersion::V1_21_11,
            x => ProtocolVersion::Unknown(x),
        }
    }

    /// Wire protocol ID.
    pub fn id(&self) -> u32 {
        match self {
            ProtocolVersion::V1_6_1 => 73,
            ProtocolVersion::V1_6_2 => 74,
            ProtocolVersion::V1_6_4 => 78,
            ProtocolVersion::V1_7_2 => 4,
            ProtocolVersion::V1_7_6 => 5,
            ProtocolVersion::V1_7_10 => 5,
            ProtocolVersion::V1_8 => 47,
            ProtocolVersion::V1_9 => 107,
            ProtocolVersion::V1_9_1 => 108,
            ProtocolVersion::V1_9_2 => 109,
            ProtocolVersion::V1_9_4 => 110,
            ProtocolVersion::V1_10 => 210,
            ProtocolVersion::V1_11 => 315,
            ProtocolVersion::V1_11_1 => 316,
            ProtocolVersion::V1_12 => 335,
            ProtocolVersion::V1_12_1 => 338,
            ProtocolVersion::V1_12_2 => 340,
            ProtocolVersion::V1_13 => 393,
            ProtocolVersion::V1_13_1 => 401,
            ProtocolVersion::V1_13_2 => 404,
            ProtocolVersion::V1_14 => 477,
            ProtocolVersion::V1_14_1 => 480,
            ProtocolVersion::V1_14_2 => 485,
            ProtocolVersion::V1_14_3 => 490,
            ProtocolVersion::V1_14_4 => 498,
            ProtocolVersion::V1_15 => 573,
            ProtocolVersion::V1_15_1 => 575,
            ProtocolVersion::V1_15_2 => 578,
            ProtocolVersion::V1_16 => 735,
            ProtocolVersion::V1_16_1 => 736,
            ProtocolVersion::V1_16_2 => 751,
            ProtocolVersion::V1_16_3 => 753,
            ProtocolVersion::V1_16_4 => 754,
            ProtocolVersion::V1_16_5 => 754,
            ProtocolVersion::V1_17 => 755,
            ProtocolVersion::V1_17_1 => 756,
            ProtocolVersion::V1_18 => 757,
            ProtocolVersion::V1_18_2 => 758,
            ProtocolVersion::V1_19 => 759,
            ProtocolVersion::V1_19_1 => 760,
            ProtocolVersion::V1_19_3 => 761,
            ProtocolVersion::V1_19_4 => 762,
            ProtocolVersion::V1_20 => 763,
            ProtocolVersion::V1_20_2 => 764,
            ProtocolVersion::V1_20_4 => 765,
            ProtocolVersion::V1_20_6 => 766,
            ProtocolVersion::V1_21 => 767,
            ProtocolVersion::V1_21_2 => 768,
            ProtocolVersion::V1_21_4 => 769,
            ProtocolVersion::V1_21_5 => 770,
            ProtocolVersion::V1_21_6 => 771,
            ProtocolVersion::V1_21_8 => 772,
            ProtocolVersion::V1_21_9 => 773,
            ProtocolVersion::V1_21_11 => 774,
            ProtocolVersion::Unknown(x) => *x,
        }
    }

    pub fn is_supported(&self) -> bool {
        !matches!(self, ProtocolVersion::Unknown(_))
    }

    /// Coarse-grained family used for converter routing.
    pub fn epoch(&self) -> Epoch {
        match self {
            ProtocolVersion::V1_6_1 | ProtocolVersion::V1_6_2 | ProtocolVersion::V1_6_4 => {
                Epoch::PreNetty
            },
            ProtocolVersion::V1_7_2 | ProtocolVersion::V1_7_6 | ProtocolVersion::V1_7_10 => {
                Epoch::V1_7
            },
            ProtocolVersion::V1_8 => Epoch::V1_8,
            ProtocolVersion::V1_9
            | ProtocolVersion::V1_9_1
            | ProtocolVersion::V1_9_2
            | ProtocolVersion::V1_9_4
            | ProtocolVersion::V1_10
            | ProtocolVersion::V1_11
            | ProtocolVersion::V1_11_1
            | ProtocolVersion::V1_12
            | ProtocolVersion::V1_12_1
            | ProtocolVersion::V1_12_2 => Epoch::V1_9_To_1_12,
            ProtocolVersion::V1_13
            | ProtocolVersion::V1_13_1
            | ProtocolVersion::V1_13_2
            | ProtocolVersion::V1_14
            | ProtocolVersion::V1_14_1
            | ProtocolVersion::V1_14_2
            | ProtocolVersion::V1_14_3
            | ProtocolVersion::V1_14_4
            | ProtocolVersion::V1_15
            | ProtocolVersion::V1_15_1
            | ProtocolVersion::V1_15_2 => Epoch::V1_13_To_1_15,
            ProtocolVersion::V1_16
            | ProtocolVersion::V1_16_1
            | ProtocolVersion::V1_16_2
            | ProtocolVersion::V1_16_3
            | ProtocolVersion::V1_16_4
            | ProtocolVersion::V1_16_5 => Epoch::V1_16,
            ProtocolVersion::V1_17
            | ProtocolVersion::V1_17_1
            | ProtocolVersion::V1_18
            | ProtocolVersion::V1_18_2 => Epoch::V1_17_To_1_18,
            ProtocolVersion::V1_19
            | ProtocolVersion::V1_19_1
            | ProtocolVersion::V1_19_3
            | ProtocolVersion::V1_19_4 => Epoch::V1_19,
            ProtocolVersion::V1_20
            | ProtocolVersion::V1_20_2
            | ProtocolVersion::V1_20_4
            | ProtocolVersion::V1_20_6 => Epoch::V1_20,
            ProtocolVersion::V1_21
            | ProtocolVersion::V1_21_2
            | ProtocolVersion::V1_21_4
            | ProtocolVersion::V1_21_5
            | ProtocolVersion::V1_21_6
            | ProtocolVersion::V1_21_8
            | ProtocolVersion::V1_21_9
            | ProtocolVersion::V1_21_11 => Epoch::V1_21Plus,
            ProtocolVersion::Unknown(_) => Epoch::Unknown,
        }
    }

    // ── Feature predicates ───────────────────────────────────────────────
    // Prefer these over bare `match self` ladders at call sites: each one
    // corresponds to a documented wire-protocol boundary on minecraft.wiki.

    /// True for 1.6.x — completely different protocol shape (no varint
    /// framing, hardcoded packet IDs, no Login phase).
    pub fn is_pre_netty(&self) -> bool {
        matches!(self.epoch(), Epoch::PreNetty)
    }

    /// True for 1.13+ — the "flattening" that gave every block/item its own
    /// numeric ID and switched many packets to string-keyed registry refs.
    pub fn is_flattened(&self) -> bool {
        self.epoch() >= Epoch::V1_13_To_1_15
    }

    /// True for 1.20.2+ (proto 764) — the version that introduced the
    /// Configuration state between Login and Play.  Note that `Epoch::V1_20`
    /// alone is *not* sufficient because it also covers 1.20/1.20.1 (proto
    /// 763) which still ship LoginSuccess → Play.
    pub fn has_configuration_phase(&self) -> bool {
        self.id() >= 764
    }

    /// True for 1.19+ — clientbound chat is split into SystemChat /
    /// PlayerChat, and ServerboundChatMessage carries signing data.
    pub fn has_chat_signing(&self) -> bool {
        self.epoch() >= Epoch::V1_19
    }

    /// True for 1.19.3+ (proto 761) — ServerboundLoginStart carries an
    /// `Option<UUID>` field (bool prefix). 1.20.2+ promoted it to a
    /// mandatory `UUID` (no bool prefix) — see [`Self::has_mandatory_login_start_uuid`].
    pub fn has_login_start_uuid(&self) -> bool {
        self.id() >= 761
    }

    /// True for 1.20.2+ (proto 764) — ServerboundLoginStart carries an
    /// always-present `UUID` field (no `Option<>` bool prefix).
    pub fn has_mandatory_login_start_uuid(&self) -> bool {
        self.id() >= 764
    }

    /// Bucket any version onto a [`CanonicalVersion`] — i.e. one of the
    /// versions that has a concrete typed-packet module in `versions::`. Used
    /// at dispatch sites that map `ProtocolVersion` to a typed packet builder.
    pub fn canonical_typed_packet_version(&self) -> CanonicalVersion {
        match self.epoch() {
            Epoch::PreNetty => CanonicalVersion::V1_6_4,
            Epoch::V1_7 => CanonicalVersion::V1_7_10,
            Epoch::V1_8 => CanonicalVersion::V1_8,
            Epoch::V1_9_To_1_12 => CanonicalVersion::V1_12_2,
            Epoch::V1_13_To_1_15 => CanonicalVersion::V1_15_2,
            Epoch::V1_16 => CanonicalVersion::V1_16_5,
            Epoch::V1_17_To_1_18 => CanonicalVersion::V1_18_2,
            Epoch::V1_19 => CanonicalVersion::V1_19_4,
            Epoch::V1_20 => CanonicalVersion::V1_20_4,
            Epoch::V1_21Plus => CanonicalVersion::V1_21,
            Epoch::Unknown => CanonicalVersion::V1_12_2,
        }
    }
}

/// The subset of `ProtocolVersion` values that have first-class typed-packet
/// modules under `kojacoord_protocol::versions::`. Returned by
/// [`ProtocolVersion::canonical_typed_packet_version`] so dispatch matches are
/// exhaustive.
/// Top-level Minecraft client edition.
///
/// The proxy is currently Java-only end-to-end, but Bedrock support is
/// on the roadmap — the enum exists now so call sites that need to
/// branch on edition can be written in terms of `MinecraftEdition`
/// rather than ad-hoc string checks, and so the inevitable Bedrock
/// path doesn't require touching every dispatch site again.
///
/// Default is `Java` everywhere the edition isn't explicitly known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MinecraftEdition {
    /// Java Edition (formerly Minecraft: Java Edition). Uses the
    /// Notchian TCP/varint-framed protocol covered by this crate.
    /// Default — every existing dispatch site is Java today.
    #[default]
    Java,
    /// Bedrock Edition. UDP/RakNet-framed. Wire shape, packet IDs and
    /// auth flow are completely different from Java; the proxy's
    /// current handlers will refuse Bedrock connections cleanly until
    /// the Bedrock pipeline lands.
    Bedrock,
}

impl MinecraftEdition {
    /// Short kebab-case identifier for telemetry / logs.
    pub fn slug(self) -> &'static str {
        match self {
            Self::Java => "java",
            Self::Bedrock => "bedrock",
        }
    }

    /// Whether this edition is implemented end-to-end by the proxy
    /// today. Bedrock returns `false` until the dedicated pipeline
    /// lands; callers handling an "unsupported" path should use the
    /// edition's `.slug()` in their error/disconnect message.
    pub fn is_implemented(self) -> bool {
        matches!(self, Self::Java)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum CanonicalVersion {
    V1_6_4,
    V1_7_10,
    V1_8,
    V1_12_2,
    V1_15_2,
    V1_16_5,
    V1_18_2,
    V1_19_4,
    V1_20_4,
    V1_21,
}

impl CanonicalVersion {
    pub fn as_protocol_version(self) -> ProtocolVersion {
        match self {
            CanonicalVersion::V1_6_4 => ProtocolVersion::V1_6_4,
            CanonicalVersion::V1_7_10 => ProtocolVersion::V1_7_10,
            CanonicalVersion::V1_8 => ProtocolVersion::V1_8,
            CanonicalVersion::V1_12_2 => ProtocolVersion::V1_12_2,
            CanonicalVersion::V1_15_2 => ProtocolVersion::V1_15_2,
            CanonicalVersion::V1_16_5 => ProtocolVersion::V1_16_5,
            CanonicalVersion::V1_18_2 => ProtocolVersion::V1_18_2,
            CanonicalVersion::V1_19_4 => ProtocolVersion::V1_19_4,
            CanonicalVersion::V1_20_4 => ProtocolVersion::V1_20_4,
            CanonicalVersion::V1_21 => ProtocolVersion::V1_21,
        }
    }
}

pub struct VersionRegistry;

impl VersionRegistry {
    /// Every known protocol ID, kept sorted for nearest-match scanning.
    const SUPPORTED: &'static [u32] = &[
        4, 5, 47, 73, 74, 78, 107, 108, 109, 110, 210, 315, 316, 335, 338, 340, 393, 401, 404, 477,
        480, 485, 490, 498, 573, 575, 578, 735, 736, 751, 753, 754, 755, 756, 757, 758, 759, 760,
        761, 762, 763, 764, 765, 766, 767, 768, 769, 770,
    ];

    /// Resolve any wire protocol ID to the closest known version. Used so an
    /// otherwise-unknown client (snapshot, new release we haven't catalogued)
    /// at least gets the nearest converter applied as a best effort.
    pub fn nearest(protocol_id: u32) -> ProtocolVersion {
        let exact = ProtocolVersion::from_id(protocol_id);
        if exact.is_supported() {
            return exact;
        }
        let best = Self::SUPPORTED
            .iter()
            .copied()
            .min_by_key(|&s| (s as i64 - protocol_id as i64).unsigned_abs())
            .unwrap_or(340);
        ProtocolVersion::from_id(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_versions_roundtrip() {
        for &id in VersionRegistry::SUPPORTED {
            let v = ProtocolVersion::from_id(id);
            assert!(v.is_supported(), "id {id} should be supported");
            assert_eq!(v.id(), id);
        }
    }

    #[test]
    fn v1_7_10_recognized() {
        assert_eq!(ProtocolVersion::from_id(5), ProtocolVersion::V1_7_10);
    }

    #[test]
    fn v1_6_4_recognized() {
        assert_eq!(ProtocolVersion::from_id(78), ProtocolVersion::V1_6_4);
    }

    #[test]
    fn nearest_exact() {
        assert_eq!(VersionRegistry::nearest(47), ProtocolVersion::V1_8);
        assert_eq!(VersionRegistry::nearest(5), ProtocolVersion::V1_7_10);
        assert_eq!(VersionRegistry::nearest(340), ProtocolVersion::V1_12_2);
    }

    #[test]
    fn nearest_between_versions() {
        let v = VersionRegistry::nearest(400);
        // 400 sits between 393 (1.13) and 401 (1.13.1); 401 wins by distance 1.
        assert_eq!(v, ProtocolVersion::V1_13_1);
    }

    #[test]
    fn epoch_grouping_matches_dispatch_table() {
        assert_eq!(ProtocolVersion::V1_12_2.epoch(), Epoch::V1_9_To_1_12);
        assert_eq!(ProtocolVersion::V1_8.epoch(), Epoch::V1_8);
        assert_eq!(ProtocolVersion::V1_16_5.epoch(), Epoch::V1_16);
        assert_eq!(ProtocolVersion::V1_21.epoch(), Epoch::V1_21Plus);
    }
}
