//! Configuration for the Mojang Realms backend bridge.
//!
//! A Realm is not a fixed address: it is reached by authenticating to the
//! Realms web API with a Microsoft "service account" (a bot account that owns
//! or is invited to the realm), asking it for an ephemeral `ip:port`, then
//! logging into that address as a genuine online-mode client. This config
//! captures the service-account credentials and the realm→name mapping the
//! operator wants exposed as backends.
//!
//! Lives in its own module (not the main `kojacoord_config` schema) so the
//! Realms feature stays self-contained; the proxy loads it from a dedicated
//! `[realms]` section / file and converts each [`RealmEntry`] into a routable
//! backend at startup.

use serde::{Deserialize, Serialize};

/// Top-level Realms bridge configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RealmsConfig {
    /// Master switch. When false the bridge registers no realm backends.
    #[serde(default)]
    pub enabled: bool,

    /// The Microsoft service account used to authenticate to the Realms API
    /// and to log in to the realm's game server. It must own or be invited to
    /// every realm listed in [`Self::realms`].
    #[serde(default)]
    pub service_account: ServiceAccountConfig,

    /// Realms to expose as named backends. Each becomes routable like an
    /// ordinary `[[servers]]` entry.
    #[serde(default)]
    pub realms: Vec<RealmEntry>,

    /// Minecraft version string sent in the Realms API `version` cookie and
    /// used to negotiate the game-server login (e.g. "1.21.11"). Realms only
    /// accepts versions it currently runs, so this must track the latest
    /// release the proxy supports.
    #[serde(default = "default_client_version")]
    pub client_version: String,

    /// Override the Realms API base URL (e.g. for the prerelease environment).
    /// Defaults to the production PC endpoint.
    #[serde(default = "default_api_base")]
    pub api_base_url: String,
}

/// Microsoft service-account credentials.
///
/// The proxy needs a live Minecraft `access_token` plus the account's profile
/// (`uuid` / `username`). These can be supplied directly (short-lived, refreshed
/// out of band) or — preferred — derived from a long-lived MSA `refresh_token`
/// that the bridge exchanges through the Xbox/Minecraft auth chain on startup
/// and renews before expiry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceAccountConfig {
    /// Account username (gamertag/profile name). Sent in the `user` cookie and
    /// as the LoginStart name to the realm.
    #[serde(default)]
    pub username: String,

    /// Account profile UUID (hyphenated or not; parsed leniently).
    #[serde(default)]
    pub uuid: String,

    /// A current Minecraft services `access_token`. Optional if
    /// [`Self::msa_refresh_token`] is set (the bridge will mint one).
    #[serde(default)]
    pub access_token: Option<String>,

    /// Long-lived Microsoft OAuth refresh token. When present the bridge runs
    /// the XBL→XSTS→Minecraft chain to obtain/refresh `access_token` and the
    /// profile automatically. (Refresh wiring is staged separately.)
    #[serde(default)]
    pub msa_refresh_token: Option<String>,
}

/// One realm exposed as a backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmEntry {
    /// Backend name used by routing rules / `/server`.
    pub name: String,

    /// The numeric Realms world id (from `GET /worlds`).
    pub id: i64,
}

fn default_client_version() -> String {
    "1.21.11".to_string()
}

fn default_api_base() -> String {
    "https://pc.realms.minecraft.net".to_string()
}
