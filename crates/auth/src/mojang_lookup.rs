//! Mojang username → real UUID lookup.
//!
//! Pre-1.7 clients (1.6.x and older) authenticated through the
//! `session.minecraft.net` endpoint Mojang shut down in 2014, so we
//! can't run a true Yggdrasil session against them. Treating every
//! 1.6.x player as a NAMESPACE_OID offline UUID would make their
//! `cached_profiles` row useless — the cache is keyed by the **real**
//! UUID written when they joined on 1.7+.
//!
//! This module fills that gap with a one-shot call to the public
//! `api.mojang.com/users/profiles/minecraft/<username>` endpoint,
//! which returns the real account UUID (dashed-stripped) for any
//! currently-existing Minecraft.net username. 404 means the username
//! doesn't belong to a paid account.
//!
//! The lookup is what backs the proxy's 1.6.x cached-profile recovery
//! path. In `online_mode = true` deployments, a 404 here also gates
//! the legacy login: there's no way to verify ownership of a name
//! that doesn't belong to a real account, so we must reject the
//! connection rather than let an impostor claim a paid name.

use std::time::Duration;
use uuid::Uuid;

/// Errors from `resolve_mojang_uuid`.
#[derive(Debug, thiserror::Error)]
pub enum MojangLookupError {
    /// The requested username does not belong to any paid Minecraft
    /// account, OR Mojang's API returned a different "not found"
    /// response. The proxy treats this as "no real UUID exists".
    #[error("no Mojang account exists for username `{0}`")]
    NotFound(String),
    /// Network / transport failure. The proxy can choose to fail
    /// open (proceed with an offline UUID) or fail closed (reject)
    /// depending on `online_mode`.
    #[error("Mojang API request failed: {0}")]
    Network(String),
    /// Mojang returned a 200 with a malformed body. Very rare; treat
    /// as a network failure for retry purposes.
    #[error("Mojang API returned an unparseable response: {0}")]
    Parse(String),
}

/// JSON wire shape of the `users/profiles/minecraft/<name>` response.
#[derive(Debug, Clone, serde::Deserialize)]
struct MojangProfileLookup {
    /// 32-char hex UUID with no hyphens (Mojang's canonical wire
    /// format for this endpoint). We re-hyphenate it via
    /// `Uuid::parse_str`.
    id: String,
    /// Canonical username casing as Mojang stores it. We discard
    /// this here — callers already have the requested username and
    /// rely on the proxy's case-insensitive matching downstream.
    #[serde(rename = "name")]
    _name: Option<String>,
}

/// Resolve a username to its real Mojang account UUID.
///
/// The call is bounded to a 4-second total budget (matching how long
/// a 1.6.x client will sit on the login screen before retrying), so a
/// flaky network can't hold up the login forever. Returns `NotFound`
/// for HTTP 404 / 204 / 200-with-empty-body — all of which Mojang
/// uses to mean "no such account today".
pub async fn resolve_mojang_uuid(username: &str) -> Result<Uuid, MojangLookupError> {
    let trimmed = username.trim();
    if trimmed.is_empty() {
        return Err(MojangLookupError::NotFound(username.to_string()));
    }

    let url = format!(
        "https://api.mojang.com/users/profiles/minecraft/{}",
        trimmed
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .user_agent("kojacoord-proxy/1.0 (Mojang UUID lookup)")
        .build()
        .map_err(|e| MojangLookupError::Network(e.to_string()))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| MojangLookupError::Network(e.to_string()))?;

    let status = resp.status();
    // 204 No Content is the historical "username doesn't exist"
    // response; modern Mojang returns 404 instead but we accept both.
    if status.as_u16() == 204 || status.as_u16() == 404 {
        return Err(MojangLookupError::NotFound(trimmed.to_string()));
    }
    if !status.is_success() {
        return Err(MojangLookupError::Network(format!(
            "Mojang API returned HTTP {}",
            status
        )));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| MojangLookupError::Network(e.to_string()))?;
    if body.trim().is_empty() {
        return Err(MojangLookupError::NotFound(trimmed.to_string()));
    }

    let parsed: MojangProfileLookup =
        serde_json::from_str(&body).map_err(|e| MojangLookupError::Parse(e.to_string()))?;

    // Re-insert the hyphens. Mojang's wire format is the canonical
    // hyphen-stripped form `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`.
    if parsed.id.len() != 32 {
        return Err(MojangLookupError::Parse(format!(
            "unexpected UUID length {} in Mojang reply",
            parsed.id.len()
        )));
    }
    let hyphenated = format!(
        "{}-{}-{}-{}-{}",
        &parsed.id[0..8],
        &parsed.id[8..12],
        &parsed.id[12..16],
        &parsed.id[16..20],
        &parsed.id[20..32],
    );
    Uuid::parse_str(&hyphenated).map_err(|e| MojangLookupError::Parse(e.to_string()))
}
