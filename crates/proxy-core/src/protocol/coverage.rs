//! Self-reported converter coverage map.
//!
//! Each cross-version converter (`v1_8_to_modern`, `v1_12_2_to_v1_16_5`,
//! …) registers what it actually handles here; the resulting
//! `ProtocolCoverage` is exposed via the management API so operators
//! can see at a glance which `(from, to)` pairs the proxy can bridge
//! losslessly versus which fall back to passthrough.
//!
//! Adding a converter ≠ registering coverage — the entries below are
//! the authoritative source of truth, so a new converter has to drop a
//! `ConverterInfo` in for it to show up.

use kojacoord_protocol::{CanonicalVersion, Epoch, ProtocolVersion};
use std::collections::HashMap;

/// Directional `(from, to)` lookup key. `from == to` is a passthrough
/// case the coverage map treats specially.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VersionPair {
    pub from: ProtocolVersion,
    pub to: ProtocolVersion,
}

impl VersionPair {
    pub fn new(from: ProtocolVersion, to: ProtocolVersion) -> Self {
        Self { from, to }
    }

    pub fn epoch_pair(&self) -> (Epoch, Epoch) {
        (self.from.epoch(), self.to.epoch())
    }

    pub fn canonical_pair(&self) -> (CanonicalVersion, CanonicalVersion) {
        (
            self.from.canonical_typed_packet_version(),
            self.to.canonical_typed_packet_version(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageStatus {
    /// Every packet the wiki documents for this pair is handled.
    Complete,
    /// Most packets work; the converter intentionally falls back to
    /// passthrough for known-untranslatable packet families (e.g. signed
    /// chat across the 1.18→1.19 boundary).
    Partial,
    /// No converter registered. Relay will passthrough untouched —
    /// usually with broken results if the wire format differs.
    Missing,
    /// `from == to`; no translation needed.
    SameVersion,
}

#[derive(Debug, Clone)]
pub struct ConverterInfo {
    pub from: ProtocolVersion,
    pub to: ProtocolVersion,
    pub status: CoverageStatus,
    /// Path of the implementing module, e.g. `"v1_12_2_to_v1_16_5"`.
    pub module: String,
    pub description: String,
    /// Number of distinct packet ids the converter knows how to rewrite.
    /// Same packet in both directions counts twice.
    pub packet_count: usize,
}

/// Coverage tracker. Three indices share the same data at different
/// granularities so callers can answer "is the (1.12.2, 1.16.5) pair
/// covered" (precise), "is anything in the 1.9→1.20 family covered"
/// (epoch-level), and the per-canonical-version case sitting in
/// between.
pub struct ProtocolCoverage {
    coverage: HashMap<(Epoch, Epoch), CoverageStatus>,
    canonical_coverage: HashMap<(CanonicalVersion, CanonicalVersion), CoverageStatus>,
    converters: HashMap<(ProtocolVersion, ProtocolVersion), ConverterInfo>,
}

impl ProtocolCoverage {
    pub fn new() -> Self {
        let mut coverage = HashMap::new();
        let mut canonical_coverage = HashMap::new();
        let mut converters = HashMap::new();

        // Initialize coverage based on actual converter implementations
        // Same-version pairs are always complete
        for epoch in &[
            Epoch::PreNetty,
            Epoch::V1_7,
            Epoch::V1_8,
            Epoch::V1_9_To_1_12,
            Epoch::V1_13_To_1_15,
            Epoch::V1_16,
            Epoch::V1_17_To_1_18,
            Epoch::V1_19,
            Epoch::V1_20,
            Epoch::V1_21Plus,
        ] {
            coverage.insert((*epoch, *epoch), CoverageStatus::Complete);
        }

        // Same canonical versions are complete
        for canonical in &[
            CanonicalVersion::V1_6_4,
            CanonicalVersion::V1_7_10,
            CanonicalVersion::V1_8,
            CanonicalVersion::V1_12_2,
            CanonicalVersion::V1_16_5,
            CanonicalVersion::V1_20_4,
        ] {
            canonical_coverage.insert((*canonical, *canonical), CoverageStatus::Complete);
        }

        // Register actual converters from the converter module
        Self::register_converter(
            &mut coverage,
            &mut canonical_coverage,
            &mut converters,
            ProtocolVersion::V1_8,
            ProtocolVersion::V1_7_10,
            "v1_8_to_v1_7",
            "1.8 → 1.7 server-to-client conversion",
            50,
        );

        Self::register_converter(
            &mut coverage,
            &mut canonical_coverage,
            &mut converters,
            ProtocolVersion::V1_7_10,
            ProtocolVersion::V1_8,
            "v1_7_to_v1_8",
            "1.7 → 1.8 bidirectional conversion",
            60,
        );

        Self::register_converter(
            &mut coverage,
            &mut canonical_coverage,
            &mut converters,
            ProtocolVersion::V1_6_4,
            ProtocolVersion::V1_12_2,
            "v1_6_4_to_v1_12_2",
            "1.6.4 → 1.12.2 conversion",
            45,
        );

        Self::register_converter(
            &mut coverage,
            &mut canonical_coverage,
            &mut converters,
            ProtocolVersion::V1_6_4,
            ProtocolVersion::V1_16_5,
            "v1_6_4_to_v1_16_5",
            "1.6.4 → 1.16.5 conversion",
            40,
        );

        Self::register_converter(
            &mut coverage,
            &mut canonical_coverage,
            &mut converters,
            ProtocolVersion::V1_12_2,
            ProtocolVersion::V1_16_5,
            "v1_12_2_to_v1_16_5",
            "1.12.2 → 1.16.5 bidirectional conversion",
            55,
        );

        Self::register_converter(
            &mut coverage,
            &mut canonical_coverage,
            &mut converters,
            ProtocolVersion::V1_16_5,
            ProtocolVersion::V1_20_4,
            "v1_16_5_to_v1_20_4",
            "1.16.5 → 1.20.4 bidirectional conversion",
            35,
        );

        Self::register_converter(
            &mut coverage,
            &mut canonical_coverage,
            &mut converters,
            ProtocolVersion::V1_8,
            ProtocolVersion::V1_16_5,
            "v1_8_to_modern",
            "1.8 → modern versions conversion",
            70,
        );

        Self {
            coverage,
            canonical_coverage,
            converters,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn register_converter(
        coverage: &mut HashMap<(Epoch, Epoch), CoverageStatus>,
        canonical_coverage: &mut HashMap<(CanonicalVersion, CanonicalVersion), CoverageStatus>,
        converters: &mut HashMap<(ProtocolVersion, ProtocolVersion), ConverterInfo>,
        from: ProtocolVersion,
        to: ProtocolVersion,
        module: &str,
        description: &str,
        packet_count: usize,
    ) {
        let from_epoch = from.epoch();
        let to_epoch = to.epoch();
        let from_canonical = from.canonical_typed_packet_version();
        let to_canonical = to.canonical_typed_packet_version();

        coverage.insert((from_epoch, to_epoch), CoverageStatus::Complete);
        coverage.insert((to_epoch, from_epoch), CoverageStatus::Complete);
        canonical_coverage.insert((from_canonical, to_canonical), CoverageStatus::Complete);
        canonical_coverage.insert((to_canonical, from_canonical), CoverageStatus::Complete);

        converters.insert(
            (from, to),
            ConverterInfo {
                from,
                to,
                status: CoverageStatus::Complete,
                module: module.to_string(),
                description: description.to_string(),
                packet_count,
            },
        );

        converters.insert(
            (to, from),
            ConverterInfo {
                from: to,
                to: from,
                status: CoverageStatus::Complete,
                module: module.to_string(),
                description: format!("{} (reverse)", description),
                packet_count,
            },
        );
    }

    /// Get coverage status for a version pair
    pub fn get_status(&self, from: ProtocolVersion, to: ProtocolVersion) -> CoverageStatus {
        if from == to {
            return CoverageStatus::SameVersion;
        }

        // Check canonical coverage first
        let (from_canonical, to_canonical) = (
            from.canonical_typed_packet_version(),
            to.canonical_typed_packet_version(),
        );
        if let Some(&status) = self.canonical_coverage.get(&(from_canonical, to_canonical)) {
            return status;
        }

        // Fall back to epoch coverage
        let (from_epoch, to_epoch) = (from.epoch(), to.epoch());
        *self
            .coverage
            .get(&(from_epoch, to_epoch))
            .unwrap_or(&CoverageStatus::Missing)
    }

    /// Get detailed converter information
    pub fn get_converter_info(
        &self,
        from: ProtocolVersion,
        to: ProtocolVersion,
    ) -> Option<&ConverterInfo> {
        self.converters.get(&(from, to))
    }

    /// Mark a version pair as complete
    pub fn mark_complete(&mut self, from: Epoch, to: Epoch) {
        self.coverage.insert((from, to), CoverageStatus::Complete);
    }

    /// Mark a canonical version pair as complete
    pub fn mark_canonical_complete(&mut self, from: CanonicalVersion, to: CanonicalVersion) {
        self.canonical_coverage
            .insert((from, to), CoverageStatus::Complete);
    }

    /// Mark a version pair as partial
    pub fn mark_partial(&mut self, from: Epoch, to: Epoch) {
        self.coverage.insert((from, to), CoverageStatus::Partial);
    }

    /// Get all missing converters by epoch
    pub fn get_missing(&self) -> Vec<(Epoch, Epoch)> {
        let all_epochs = vec![
            Epoch::PreNetty,
            Epoch::V1_7,
            Epoch::V1_8,
            Epoch::V1_9_To_1_12,
            Epoch::V1_13_To_1_15,
            Epoch::V1_16,
            Epoch::V1_17_To_1_18,
            Epoch::V1_19,
            Epoch::V1_20,
            Epoch::V1_21Plus,
        ];

        let mut missing = Vec::new();
        for &from in &all_epochs {
            for &to in &all_epochs {
                if from != to
                    && self
                        .coverage
                        .get(&(from, to))
                        .map_or(true, |s| *s == CoverageStatus::Missing)
                {
                    missing.push((from, to));
                }
            }
        }
        missing
    }

    /// Get all missing converters by canonical version
    pub fn get_missing_canonical(&self) -> Vec<(CanonicalVersion, CanonicalVersion)> {
        let all_canonical = vec![
            CanonicalVersion::V1_6_4,
            CanonicalVersion::V1_7_10,
            CanonicalVersion::V1_8,
            CanonicalVersion::V1_12_2,
            CanonicalVersion::V1_16_5,
            CanonicalVersion::V1_20_4,
        ];

        let mut missing = Vec::new();
        for &from in &all_canonical {
            for &to in &all_canonical {
                if from != to
                    && self
                        .canonical_coverage
                        .get(&(from, to))
                        .map_or(true, |s| *s == CoverageStatus::Missing)
                {
                    missing.push((from, to));
                }
            }
        }
        missing
    }

    pub fn get_all_converters(&self) -> Vec<&ConverterInfo> {
        self.converters.values().collect()
    }

    /// Percentage of *epoch* pairs (e.g. `V1_8 ↔ V1_16`) marked
    /// `Complete`. Same-version pairs are excluded from the denominator
    /// since they're trivially complete.
    pub fn coverage_percentage(&self) -> f64 {
        let all_epochs = vec![
            Epoch::PreNetty,
            Epoch::V1_7,
            Epoch::V1_8,
            Epoch::V1_9_To_1_12,
            Epoch::V1_13_To_1_15,
            Epoch::V1_16,
            Epoch::V1_17_To_1_18,
            Epoch::V1_19,
            Epoch::V1_20,
            Epoch::V1_21Plus,
        ];

        let total = all_epochs.len() * (all_epochs.len() - 1); // Exclude same-version pairs
        let complete = self
            .coverage
            .values()
            .filter(|s| **s == CoverageStatus::Complete)
            .count();

        if total == 0 {
            0.0
        } else {
            (complete as f64 / total as f64) * 100.0
        }
    }

    /// Same shape as [`Self::coverage_percentage`] but at the finer
    /// `CanonicalVersion` granularity — useful when an epoch contains
    /// versions that diverged on the wire (e.g. 1.20.2's configuration
    /// phase split V1_20 internally).
    pub fn canonical_coverage_percentage(&self) -> f64 {
        let all_canonical = [
            CanonicalVersion::V1_6_4,
            CanonicalVersion::V1_7_10,
            CanonicalVersion::V1_8,
            CanonicalVersion::V1_12_2,
            CanonicalVersion::V1_16_5,
            CanonicalVersion::V1_20_4,
        ];

        let total = all_canonical.len() * (all_canonical.len() - 1);
        let complete = self
            .canonical_coverage
            .values()
            .filter(|s| **s == CoverageStatus::Complete)
            .count();

        if total == 0 {
            0.0
        } else {
            (complete as f64 / total as f64) * 100.0
        }
    }

    /// Human-readable dump of the entire coverage map. Used by `/coverage`
    /// in the management CLI and rendered straight to the operator
    /// console — no machine consumer, so the format can drift.
    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str("Protocol Coverage Report\n");
        report.push_str("======================\n\n");

        // Summary
        report.push_str("Summary:\n");
        report.push_str(&format!(
            "  Epoch coverage: {:.1}%\n",
            self.coverage_percentage()
        ));
        report.push_str(&format!(
            "  Canonical coverage: {:.1}%\n",
            self.canonical_coverage_percentage()
        ));
        report.push_str(&format!(
            "  Total converters: {}\n\n",
            self.converters.len()
        ));

        // Missing converters by epoch
        let missing = self.get_missing();
        if !missing.is_empty() {
            report.push_str(&format!("Missing converters (epoch): {}\n", missing.len()));
            for (from, to) in &missing {
                report.push_str(&format!("  {:?} → {:?}\n", from, to));
            }
            report.push('\n');
        }

        // Missing converters by canonical version
        let missing_canonical = self.get_missing_canonical();
        if !missing_canonical.is_empty() {
            report.push_str(&format!(
                "Missing converters (canonical): {}\n",
                missing_canonical.len()
            ));
            for (from, to) in &missing_canonical {
                report.push_str(&format!("  {:?} → {:?}\n", from, to));
            }
            report.push('\n');
        }

        // Registered converters
        report.push_str("Registered converters:\n");
        for converter in self.get_all_converters() {
            report.push_str(&format!(
                "  {:?} → {:?}: {} ({})\n",
                converter.from, converter.to, converter.module, converter.description
            ));
        }

        report
    }
}

impl Default for ProtocolCoverage {
    fn default() -> Self {
        Self::new()
    }
}

/// Each `Epoch` covers multiple wire versions; for reporting we pick a
/// canonical one to show users (typically the last patch in the
/// family).
fn epoch_to_version(epoch: Epoch) -> ProtocolVersion {
    match epoch {
        Epoch::PreNetty => ProtocolVersion::V1_6_4,
        Epoch::V1_7 => ProtocolVersion::V1_7_10,
        Epoch::V1_8 => ProtocolVersion::V1_8,
        Epoch::V1_9_To_1_12 => ProtocolVersion::V1_12_2,
        Epoch::V1_13_To_1_15 => ProtocolVersion::V1_15_2,
        Epoch::V1_16 => ProtocolVersion::V1_16_5,
        Epoch::V1_17_To_1_18 => ProtocolVersion::V1_18_2,
        Epoch::V1_19 => ProtocolVersion::V1_19_4,
        Epoch::V1_20 => ProtocolVersion::V1_20_4,
        Epoch::V1_21Plus => ProtocolVersion::V1_21,
        Epoch::Unknown => ProtocolVersion::V1_20_4,
    }
}

/// Fluent builder used by converter modules during their `register`
/// step to declare what they handle. Currently records description and
/// per-packet mappings; the mappings table is reserved for a future
/// per-packet status view (the public surface only exposes the
/// summary counts today).
pub struct ConverterBuilder {
    from_epoch: Epoch,
    to_epoch: Epoch,
    packet_mappings: HashMap<String, String>,
    description: String,
}

impl ConverterBuilder {
    pub fn new(from_epoch: Epoch, to_epoch: Epoch) -> Self {
        Self {
            from_epoch,
            to_epoch,
            packet_mappings: HashMap::new(),
            description: String::new(),
        }
    }

    /// Set converter description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    /// Add a packet ID mapping
    pub fn add_packet_mapping(&mut self, from_packet: &str, to_packet: &str) {
        self.packet_mappings
            .insert(from_packet.to_string(), to_packet.to_string());
    }

    /// Build the converter
    pub fn build(self) -> Result<ConverterInfo, String> {
        if self.packet_mappings.is_empty() {
            return Err("No packet mappings defined".into());
        }

        Ok(ConverterInfo {
            from: epoch_to_version(self.from_epoch),
            to: epoch_to_version(self.to_epoch),
            status: CoverageStatus::Complete,
            module: format!(
                "{}_to_{}",
                format!("{:?}", self.from_epoch)
                    .to_lowercase()
                    .replace("_", ""),
                format!("{:?}", self.to_epoch)
                    .to_lowercase()
                    .replace("_", "")
            ),
            description: if self.description.is_empty() {
                format!("{:?} → {:?} converter", self.from_epoch, self.to_epoch)
            } else {
                self.description
            },
            packet_count: self.packet_mappings.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_tracking() {
        let coverage = ProtocolCoverage::new();

        // Same version should be complete
        assert_eq!(
            coverage.get_status(ProtocolVersion::V1_12_2, ProtocolVersion::V1_12_2),
            CoverageStatus::SameVersion
        );

        // Known converter should be complete
        assert_eq!(
            coverage.get_status(ProtocolVersion::V1_12_2, ProtocolVersion::V1_16_5),
            CoverageStatus::Complete
        );

        // Unknown converter should be missing
        assert_eq!(
            coverage.get_status(ProtocolVersion::V1_8, ProtocolVersion::V1_21),
            CoverageStatus::Missing
        );
    }

    #[test]
    fn coverage_report() {
        let coverage = ProtocolCoverage::new();
        let report = coverage.generate_report();
        assert!(report.contains("Protocol Coverage Report"));
        assert!(report.contains("Summary:"));
        assert!(report.contains("Registered converters:"));
    }

    #[test]
    fn converter_builder() {
        let mut builder = ConverterBuilder::new(Epoch::V1_8, Epoch::V1_9_To_1_12)
            .with_description("Test converter");
        builder.add_packet_mapping("0x00", "0x00");
        builder.add_packet_mapping("0x01", "0x02");

        let converter = builder.build().unwrap();
        assert_eq!(converter.packet_count, 2);
        assert_eq!(converter.description, "Test converter");
    }

    #[test]
    fn get_all_converters() {
        let coverage = ProtocolCoverage::new();
        let converters = coverage.get_all_converters();
        assert!(!converters.is_empty());

        // Check that known converters are present
        assert!(converters
            .iter()
            .any(|c| c.module.contains("v1_12_2_to_v1_16_5")));
        assert!(converters
            .iter()
            .any(|c| c.module.contains("v1_16_5_to_v1_20_4")));
    }
}
