//! Startup update check.
//!
//! On boot the proxy asks the KojaCraft release API for the newest
//! published release and, if the running binary is older, logs a
//! prominent warning so operators know to upgrade. Best-effort: any
//! network/parse failure is logged at debug and silently ignored — a
//! missing internet connection must never block startup.

use serde::Deserialize;
use std::time::Duration;

const RELEASES_URL: &str = "https://www.kojacraft.net/api/github/releases";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Deserialize)]
struct ReleasesResponse {
    releases: Vec<Release>,
}

#[derive(Debug, Deserialize)]
struct Release {
    tag: String,
    #[serde(rename = "isLatest")]
    is_latest: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(rename = "htmlUrl", default)]
    html_url: String,
}

/// A parsed `major.minor.patch` version. Pre-release/build suffixes are
/// ignored for comparison purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SemVer(u64, u64, u64);

impl SemVer {
    /// Parse a tag like `v0.1.5`, `0.1.5`, or `0.1.5-rc1`.
    fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches(['v', 'V']);
        // Drop any pre-release/build metadata.
        let core = s.split(['-', '+']).next().unwrap_or(s);
        let mut it = core.split('.');
        let major = it.next()?.parse().ok()?;
        let minor = it.next().unwrap_or("0").parse().ok()?;
        let patch = it.next().unwrap_or("0").parse().ok()?;
        Some(SemVer(major, minor, patch))
    }
}

/// Fetch the latest release and warn if `current_version` is older.
/// Never returns an error — failures are logged and swallowed.
pub async fn check_for_updates(current_version: &str) {
    let Some(current) = SemVer::parse(current_version) else {
        tracing::debug!(
            version = current_version,
            "could not parse own version; skipping update check"
        );
        return;
    };

    let client = match reqwest::Client::builder().timeout(REQUEST_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "update check: failed to build HTTP client");
            return;
        },
    };

    let resp = match client.get(RELEASES_URL).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "update check: request failed");
            return;
        },
    };

    let body: ReleasesResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "update check: failed to parse response");
            return;
        },
    };

    // Prefer the flagged latest stable release; fall back to the
    // highest-versioned non-prerelease tag.
    let latest = body
        .releases
        .iter()
        .filter(|r| !r.prerelease)
        .filter_map(|r| SemVer::parse(&r.tag).map(|v| (v, r)))
        .max_by_key(|(v, _)| *v);

    let Some((latest_ver, latest_rel)) = latest else {
        tracing::debug!("update check: no usable releases in response");
        return;
    };

    // The API marks one release isLatest; prefer it if it parses higher.
    let flagged = body
        .releases
        .iter()
        .find(|r| r.is_latest)
        .and_then(|r| SemVer::parse(&r.tag).map(|v| (v, r)));
    let (latest_ver, latest_rel) = match flagged {
        Some((v, r)) if v >= latest_ver => (v, r),
        _ => (latest_ver, latest_rel),
    };

    if latest_ver > current {
        tracing::warn!("╔══════════════════════════════════════════════════════════════╗");
        tracing::warn!(
            "  A newer Kojacoord Proxy is available: v{}.{}.{} (you are on v{})",
            latest_ver.0,
            latest_ver.1,
            latest_ver.2,
            current_version
        );
        if !latest_rel.html_url.is_empty() {
            tracing::warn!("  Download: {}", latest_rel.html_url);
        }
        tracing::warn!("╚══════════════════════════════════════════════════════════════╝");
    } else {
        tracing::info!(version = current_version, "Kojacoord Proxy is up to date");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tags() {
        assert_eq!(SemVer::parse("v0.1.5"), Some(SemVer(0, 1, 5)));
        assert_eq!(SemVer::parse("0.1.0"), Some(SemVer(0, 1, 0)));
        assert_eq!(SemVer::parse("v1.2.3-rc1"), Some(SemVer(1, 2, 3)));
        assert_eq!(SemVer::parse("v2"), Some(SemVer(2, 0, 0)));
        assert_eq!(SemVer::parse("garbage"), None);
    }

    #[test]
    fn ordering_detects_older() {
        assert!(SemVer::parse("v0.1.5").unwrap() > SemVer::parse("v0.1.0").unwrap());
        assert!(SemVer::parse("v0.2.0").unwrap() > SemVer::parse("v0.1.9").unwrap());
        assert!(SemVer::parse("v1.0.0").unwrap() > SemVer::parse("v0.9.9").unwrap());
        assert!(SemVer::parse("v0.1.0").unwrap() == SemVer::parse("v0.1.0").unwrap());
    }
}
