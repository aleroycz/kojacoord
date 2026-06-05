//! Plugin integrity verification.
//!
//! Native plugins (`.dll`/`.so`/`.dylib`) execute with full process privileges,
//! so loading an untrusted binary is equivalent to arbitrary code execution.
//! This module gates loading behind a SHA-256 allowlist: the operator records
//! the hashes of plugins they trust, and any binary whose hash is not on the
//! list is refused.
//!
//! When `require_verification` is enabled but no hashes are configured, loading
//! fails closed. When verification is not required and the allowlist is empty,
//! loading proceeds with a prominent security warning so the risk is never
//! silent.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

/// Verifies plugin binaries against a configured set of trusted SHA-256 hashes.
#[derive(Debug, Clone, Default)]
pub struct PluginVerifier {
    trusted_hashes: HashSet<String>,
    require_verification: bool,
}

impl PluginVerifier {
    /// Create a permissive verifier with no allowlist (loads with warnings).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a strict verifier seeded with trusted hex-encoded SHA-256 hashes.
    /// Verification is required, so unknown binaries are refused.
    pub fn with_trusted_hashes<I, S>(hashes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            trusted_hashes: hashes
                .into_iter()
                .map(|h| h.as_ref().trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
            require_verification: true,
        }
    }

    /// Require verification: when true, a binary must be on the allowlist.
    pub fn set_require_verification(&mut self, require: bool) {
        self.require_verification = require;
    }

    /// Add a single trusted hex-encoded SHA-256 hash.
    pub fn add_trusted_hash(&mut self, hash: &str) {
        self.trusted_hashes.insert(hash.trim().to_ascii_lowercase());
    }

    /// Compute the hex-encoded SHA-256 digest of a file.
    pub fn file_sha256(path: &Path) -> Result<String> {
        let bytes =
            std::fs::read(path).with_context(|| format!("reading plugin {}", path.display()))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Verify a plugin binary's integrity before it is loaded.
    ///
    /// Returns `Ok(())` if the binary is trusted (or verification is not
    /// required and no allowlist is configured), and an error otherwise.
    pub fn verify(&self, path: &Path) -> Result<()> {
        let digest = Self::file_sha256(path)?;

        if self.trusted_hashes.is_empty() {
            if self.require_verification {
                bail!(
                    "plugin verification is required but no trusted hashes are configured; \
                     refusing to load {} (sha256={})",
                    path.display(),
                    digest
                );
            }
            log::warn!(
                "SECURITY: loading UNVERIFIED native plugin {} (sha256={}). \
                 No trusted-hash allowlist is configured and native plugins run with \
                 full process privileges. Configure a plugin allowlist for production.",
                path.display(),
                digest
            );
            return Ok(());
        }

        if self.trusted_hashes.contains(&digest) {
            log::info!("verified plugin {} (sha256={})", path.display(), digest);
            Ok(())
        } else {
            bail!(
                "plugin {} failed integrity verification: sha256={} is not in the trusted allowlist",
                path.display(),
                digest
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_plugin(bytes: &[u8]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "kojacoord_test_plugin_{}.bin",
            uuid::Uuid::new_v4()
        ));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        p
    }

    #[test]
    fn permissive_allows_with_warning() {
        let path = temp_plugin(b"hello plugin");
        let v = PluginVerifier::new();
        assert!(v.verify(&path).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn strict_rejects_unknown_and_accepts_known() {
        let path = temp_plugin(b"trusted bytes");
        let digest = PluginVerifier::file_sha256(&path).unwrap();

        let bad = PluginVerifier::with_trusted_hashes(["deadbeef"]);
        assert!(bad.verify(&path).is_err());

        let good = PluginVerifier::with_trusted_hashes([digest]);
        assert!(good.verify(&path).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn require_without_allowlist_fails_closed() {
        let path = temp_plugin(b"x");
        let mut v = PluginVerifier::new();
        v.set_require_verification(true);
        assert!(v.verify(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
