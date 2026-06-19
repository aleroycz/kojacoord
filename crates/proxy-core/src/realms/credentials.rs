//! Service-account credentials for the Realms bridge.
//!
//! Both the Realms web API and the realm's game-server login need the same
//! three facts about the authenticating account: a live Minecraft
//! `access_token`, its profile `uuid`, and its `username`. [`ServiceAccount`]
//! holds them and knows how to format the Realms API `Cookie` header.
//!
//! [`RealmsCredentials`] is the live, shareable handle the rest of the bridge
//! uses. Today it wraps a static set from config; the `account()` accessor is
//! async and the inner value sits behind a lock so a future Microsoft
//! refresh-token exchanger can renew `access_token` in place without changing
//! any call sites.

use std::sync::Arc;

use tokio::sync::RwLock;
use uuid::Uuid;

use super::config::ServiceAccountConfig;
use super::RealmsError;

/// A resolved, ready-to-use account identity.
#[derive(Debug, Clone)]
pub struct ServiceAccount {
    pub access_token: String,
    pub uuid: Uuid,
    pub username: String,
}

impl ServiceAccount {
    /// The Realms `sid` cookie value: `token:<accessToken>:<undashed uuid>`.
    /// Realms expects the UUID without hyphens.
    pub fn sid_cookie(&self) -> String {
        format!("token:{}:{}", self.access_token, self.uuid.simple())
    }

    /// The full `Cookie` header value required by every Realms API request:
    /// `sid=…; user=<name>; version=<mcVersion>`.
    pub fn cookie_header(&self, client_version: &str) -> String {
        format!(
            "sid={};user={};version={}",
            self.sid_cookie(),
            self.username,
            client_version
        )
    }
}

/// Shareable credentials handle. Clone is cheap (`Arc`).
#[derive(Clone)]
pub struct RealmsCredentials {
    inner: Arc<RwLock<ServiceAccount>>,
}

impl RealmsCredentials {
    /// Build from the `[realms.service_account]` config block. Fails if the
    /// uuid can't be parsed or no `access_token` is present.
    pub fn from_config(cfg: &ServiceAccountConfig) -> Result<Self, RealmsError> {
        let uuid = parse_uuid(&cfg.uuid).ok_or_else(|| {
            RealmsError::Config(format!("invalid service account uuid: {:?}", cfg.uuid))
        })?;
        let access_token = cfg
            .access_token
            .clone()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                RealmsError::Config(
                    "service account has no access_token (msa_refresh_token exchange not yet wired)"
                        .into(),
                )
            })?;
        if cfg.username.is_empty() {
            return Err(RealmsError::Config(
                "service account username is empty".into(),
            ));
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(ServiceAccount {
                access_token,
                uuid,
                username: cfg.username.clone(),
            })),
        })
    }

    /// Current account snapshot. Async + locked so a refresh implementation can
    /// renew the token transparently here later.
    pub async fn account(&self) -> Result<ServiceAccount, RealmsError> {
        Ok(self.inner.read().await.clone())
    }

    /// Replace the live access token (used by a future refresher).
    pub async fn set_access_token(&self, token: String) {
        self.inner.write().await.access_token = token;
    }
}

/// Parse a UUID that may be hyphenated or undashed (Realms/Mojang use both).
fn parse_uuid(s: &str) -> Option<Uuid> {
    Uuid::parse_str(s)
        .ok()
        .or_else(|| Uuid::parse_str(&insert_hyphens(s)).ok())
}

fn insert_hyphens(s: &str) -> String {
    if s.len() != 32 {
        return s.to_string();
    }
    format!(
        "{}-{}-{}-{}-{}",
        &s[0..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct() -> ServiceAccount {
        ServiceAccount {
            access_token: "TOKEN".into(),
            uuid: Uuid::parse_str("069a79f4-44e9-4726-a5be-fca90e38aaf5").unwrap(),
            username: "Notch".into(),
        }
    }

    #[test]
    fn sid_cookie_uses_undashed_uuid() {
        assert_eq!(
            acct().sid_cookie(),
            "token:TOKEN:069a79f444e94726a5befca90e38aaf5"
        );
    }

    #[test]
    fn cookie_header_shape() {
        assert_eq!(
            acct().cookie_header("1.21.11"),
            "sid=token:TOKEN:069a79f444e94726a5befca90e38aaf5;user=Notch;version=1.21.11"
        );
    }

    #[test]
    fn parses_undashed_uuid() {
        assert!(parse_uuid("069a79f444e94726a5befca90e38aaf5").is_some());
        assert!(parse_uuid("069a79f4-44e9-4726-a5be-fca90e38aaf5").is_some());
        assert!(parse_uuid("nonsense").is_none());
    }
}
