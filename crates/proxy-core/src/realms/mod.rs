//! Mojang Realms backend bridge.
//!
//! Lets the proxy expose a Realm as an ordinary named backend. Because a Realm
//! is online-mode and reached through an authenticated API rather than a fixed
//! address, the flow differs from the normal offline backend path:
//!
//!   1. [`api`] — authenticate to `pc.realms.minecraft.net` with the shared
//!      service account ([`credentials`]) and resolve a realm id to an
//!      ephemeral `ip:port` (polling past the boot-time 503s).
//!   2. [`login`] — connect to that address and perform a real online-mode
//!      client login ([`wire`] carries the framing + AES), authorising via the
//!      session server, ending just after LoginSuccess.
//!
//! The resulting [`login::RealmConnection`] is an AES-encrypted, compression-
//! aware stream positioned at the configuration phase — ready for the relay.
//! Self-contained: nothing here is bolted onto the existing offline backend
//! types.

pub mod api;
pub mod config;
pub mod credentials;
pub mod login;
pub mod wire;

use std::collections::HashMap;

use api::RealmsApi;
use config::RealmsConfig;
use credentials::RealmsCredentials;
use login::RealmConnection;

/// Errors surfaced by the Realms bridge.
#[derive(Debug, thiserror::Error)]
pub enum RealmsError {
    #[error("realms config error: {0}")]
    Config(String),
    #[error("realms http error: {0}")]
    Http(String),
    #[error("realms api error: {0}")]
    Api(String),
    #[error("realm login error: {0}")]
    Login(String),
    #[error("unknown realm backend: {0}")]
    UnknownRealm(String),
}

/// The bridge: owns the credentials, the API client, and the name→id map of
/// configured realms. Construct once at startup from [`RealmsConfig`], then call
/// [`Self::connect`] whenever a player should be bridged into a named realm.
pub struct RealmsBridge {
    api: RealmsApi,
    /// Backend name → realm world id.
    realms: HashMap<String, i64>,
    /// Protocol version advertised to the realm game server.
    protocol: i32,
    /// Shared HTTP client for the session-server join during login.
    http: reqwest::Client,
    creds: RealmsCredentials,
}

impl RealmsBridge {
    /// Build the bridge from config. Returns `Ok(None)` when Realms is disabled
    /// so callers can cleanly skip registration.
    pub fn from_config(cfg: &RealmsConfig, protocol: i32) -> Result<Option<Self>, RealmsError> {
        if !cfg.enabled {
            return Ok(None);
        }
        let creds = RealmsCredentials::from_config(&cfg.service_account)?;
        let api = RealmsApi::new(
            cfg.api_base_url.clone(),
            cfg.client_version.clone(),
            creds.clone(),
        );
        let realms = cfg.realms.iter().map(|r| (r.name.clone(), r.id)).collect();
        Ok(Some(Self {
            api,
            realms,
            protocol,
            http: reqwest::Client::new(),
            creds,
        }))
    }

    /// Names of the realms exposed as backends.
    pub fn backend_names(&self) -> impl Iterator<Item = &String> {
        self.realms.keys()
    }

    /// Resolve and log in to the named realm, returning a ready-to-relay
    /// connection. Performs: API join (with boot polling) → online-mode login.
    pub async fn connect(&self, backend_name: &str) -> Result<RealmConnection, RealmsError> {
        let world_id = *self
            .realms
            .get(backend_name)
            .ok_or_else(|| RealmsError::UnknownRealm(backend_name.to_string()))?;

        let join = self.api.join(world_id).await?;
        let (host, port) = join.host_port()?;
        let account = self.creds.account().await?;

        tracing::info!(
            backend = backend_name,
            world_id,
            address = %join.address,
            "bridging into realm"
        );
        login::connect(&host, port, self.protocol, &account, &self.http).await
    }
}
