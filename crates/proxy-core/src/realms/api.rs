//! Minecraft Realms web API client (`https://pc.realms.minecraft.net`).
//!
//! Spec: minecraft.wiki "Realms API". Every request carries the
//! [`ServiceAccount`] cookie; the two endpoints the bridge needs are:
//!   * `GET /worlds` — list the realms the account owns / is invited to.
//!   * `GET /worlds/v1/{id}/join/pc` — resolve a realm to an ephemeral
//!     `ip:port`. The first calls return **503** while Realms boots the
//!     instance, so [`RealmsApi::join`] polls until it's ready.

use std::time::Duration;

use serde::Deserialize;

use super::credentials::RealmsCredentials;
use super::RealmsError;

/// Max attempts to poll the join endpoint while the realm boots (503s).
const JOIN_MAX_ATTEMPTS: usize = 20;
/// Delay between join poll attempts.
const JOIN_POLL_DELAY: Duration = Duration::from_secs(3);

/// One realm as returned by `GET /worlds`.
#[derive(Debug, Clone, Deserialize)]
pub struct RealmWorld {
    pub id: i64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub motd: Option<String>,
    /// `OPEN`, `CLOSED`, or `UNINITIALIZED`.
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub expired: bool,
}

impl RealmWorld {
    pub fn is_open(&self) -> bool {
        self.state.as_deref() == Some("OPEN")
    }
}

#[derive(Debug, Deserialize)]
struct WorldsResponse {
    #[serde(default)]
    servers: Vec<RealmWorld>,
}

/// Response of `GET /worlds/v1/{id}/join/pc`.
#[derive(Debug, Clone, Deserialize)]
pub struct JoinAddress {
    /// `IP:Port` of the running realm game server.
    pub address: String,
    #[serde(rename = "pendingUpdate", default)]
    pub pending_update: bool,
}

impl JoinAddress {
    /// Split `address` into (host, port). Port defaults to 25565 if absent.
    pub fn host_port(&self) -> Result<(String, u16), RealmsError> {
        match self.address.rsplit_once(':') {
            Some((h, p)) => {
                let port = p.parse::<u16>().map_err(|_| {
                    RealmsError::Api(format!("bad join port in {:?}", self.address))
                })?;
                Ok((h.to_string(), port))
            },
            None => Ok((self.address.clone(), 25565)),
        }
    }
}

/// Realms API client. Holds a `reqwest::Client` and the configured base URL +
/// client version (sent in the cookie).
pub struct RealmsApi {
    http: reqwest::Client,
    base_url: String,
    client_version: String,
    creds: RealmsCredentials,
}

impl RealmsApi {
    pub fn new(base_url: String, client_version: String, creds: RealmsCredentials) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("kojacoord-realms-bridge")
            .build()
            .unwrap_or_default();
        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            client_version,
            creds,
        }
    }

    async fn cookie(&self) -> Result<String, RealmsError> {
        Ok(self
            .creds
            .account()
            .await?
            .cookie_header(&self.client_version))
    }

    /// `GET /worlds` — realms the service account can see.
    pub async fn list_worlds(&self) -> Result<Vec<RealmWorld>, RealmsError> {
        let cookie = self.cookie().await?;
        let resp = self
            .http
            .get(format!("{}/worlds", self.base_url))
            .header(reqwest::header::COOKIE, cookie)
            .send()
            .await
            .map_err(|e| RealmsError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(RealmsError::Api(format!(
                "GET /worlds returned {}",
                resp.status()
            )));
        }
        let parsed: WorldsResponse = resp
            .json()
            .await
            .map_err(|e| RealmsError::Api(format!("decoding /worlds: {e}")))?;
        Ok(parsed.servers)
    }

    /// Resolve a realm id to an `ip:port`, polling past the 503s Realms returns
    /// while it spins up the instance.
    pub async fn join(&self, world_id: i64) -> Result<JoinAddress, RealmsError> {
        let url = format!("{}/worlds/v1/{}/join/pc", self.base_url, world_id);
        for attempt in 1..=JOIN_MAX_ATTEMPTS {
            let cookie = self.cookie().await?;
            let resp = self
                .http
                .get(&url)
                .header(reqwest::header::COOKIE, cookie)
                .send()
                .await
                .map_err(|e| RealmsError::Http(e.to_string()))?;
            let status = resp.status();
            if status.is_success() {
                let addr: JoinAddress = resp
                    .json()
                    .await
                    .map_err(|e| RealmsError::Api(format!("decoding join response: {e}")))?;
                tracing::debug!(world_id, address = %addr.address, "realm ready");
                return Ok(addr);
            }
            // 503 = still booting; retry. 403/404 = no access / gone; fail fast.
            if status.as_u16() == 503 {
                tracing::debug!(world_id, attempt, "realm booting (503), polling");
                tokio::time::sleep(JOIN_POLL_DELAY).await;
                continue;
            }
            return Err(RealmsError::Api(format!(
                "join realm {world_id} returned {status}"
            )));
        }
        Err(RealmsError::Api(format!(
            "realm {world_id} did not become ready after {JOIN_MAX_ATTEMPTS} attempts"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_splits() {
        let a = JoinAddress {
            address: "10.0.0.5:25571".into(),
            pending_update: false,
        };
        assert_eq!(a.host_port().unwrap(), ("10.0.0.5".to_string(), 25571));
    }

    #[test]
    fn host_port_defaults_port() {
        let a = JoinAddress {
            address: "realm.example".into(),
            pending_update: false,
        };
        assert_eq!(a.host_port().unwrap(), ("realm.example".to_string(), 25565));
    }
}
