//! Backend selector GUI (`kojacoord:serverlist` plugin channel).
//!
//! Custom protocol that lets modded clients render a server-picker
//! UI inside the game without leaving the proxy. We respond to
//! `serverlist` channel queries with the current backend list plus
//! status, and act on `connect`/`modpack` channel commands by
//! transferring the player.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use uuid::Uuid;

use crate::proxy::ProxyState;

const PING_TIMEOUT: Duration = Duration::from_millis(500);
const SERVERLIST_COOLDOWN: Duration = Duration::from_secs(5);
const SERVERLIST_COOLDOWN_MAX_ENTRIES: usize = 10000;

pub const CHANNEL_SERVERLIST_MODERN: &str = "kojacoord:serverlist";
pub const CHANNEL_SERVERLIST_LEGACY: &str = "KOJACRD|SERVERS";
pub const CHANNEL_CONNECT_MODERN: &str = "kojacoord:connect";
pub const CHANNEL_CONNECT_LEGACY: &str = "KOJACRD|CONNECT";
pub const CHANNEL_MODPACK_MODERN: &str = "kojacoord:modpack";
pub const CHANNEL_MODPACK_LEGACY: &str = "KOJACRD|MODPACK";

pub const ALL_CHANNELS: &[&str] = &[
    CHANNEL_SERVERLIST_MODERN,
    CHANNEL_SERVERLIST_LEGACY,
    CHANNEL_CONNECT_MODERN,
    CHANNEL_CONNECT_LEGACY,
    CHANNEL_MODPACK_MODERN,
    CHANNEL_MODPACK_LEGACY,
];

#[inline]
pub fn is_serverlist_channel(channel: &str) -> bool {
    channel == CHANNEL_SERVERLIST_MODERN || channel == CHANNEL_SERVERLIST_LEGACY
}

#[inline]
pub fn is_connect_channel(channel: &str) -> bool {
    channel == CHANNEL_CONNECT_MODERN || channel == CHANNEL_CONNECT_LEGACY
}

#[inline]
pub fn is_modpack_channel(channel: &str) -> bool {
    channel == CHANNEL_MODPACK_MODERN || channel == CHANNEL_MODPACK_LEGACY
}

pub async fn build_serverlist_payload(state: &Arc<ProxyState>, player_uuid: Uuid) -> Vec<u8> {
    {
        let map = &state.serverlist_cooldown;
        let now = Instant::now();
        if let Some(entry) = map.get(&player_uuid) {
            if now.duration_since(*entry) < SERVERLIST_COOLDOWN {
                return b"[]".to_vec();
            }
        }
        if map.len() >= SERVERLIST_COOLDOWN_MAX_ENTRIES {
            map.retain(|_, t| now.duration_since(*t) < SERVERLIST_COOLDOWN);
        }
        map.insert(player_uuid, now);
    }

    let servers = state.server_registry.all();

    let ping_handles: Vec<_> = servers
        .iter()
        .map(|s| {
            let addr = s.address;
            tokio::spawn(async move { measure_ping(addr).await })
        })
        .collect();
    let mut pings = Vec::with_capacity(ping_handles.len());
    for handle in ping_handles {
        pings.push(handle.await.unwrap_or(None));
    }

    let entries: Vec<serde_json::Value> = servers
        .iter()
        .zip(pings)
        .map(|(s, ping)| {
            let cfg = state.config.servers.iter().find(|e| e.name == s.name);

            let max_players = cfg
                .and_then(|e| e.max_players)
                .unwrap_or(state.config.proxy.max_players);
            let display_name = cfg
                .and_then(|e| e.display_name.clone())
                .unwrap_or_else(|| s.name.clone());
            let motd = cfg.and_then(|e| e.motd.clone()).unwrap_or_default();
            let modpack = cfg.and_then(|e| e.modpack.clone());
            let modpack_version = cfg.and_then(|e| e.modpack_version.clone());
            let game_type = cfg.and_then(|e| e.game_type.clone()).unwrap_or_default();

            let reachable = ping.is_some();
            let status = if s.is_online() && reachable {
                "ONLINE"
            } else {
                "OFFLINE"
            };

            serde_json::json!({
                "name":           s.name,
                "status":         status,
                "currentPlayers": s.player_count(),
                "maxPlayers":     max_players,
                "pingMs":         ping.map(|d| d.as_millis() as u64).unwrap_or(0),
                "motd":           motd,
                "displayName":    display_name,
                "description":    motd_clone(cfg),
                "modpack":        json_opt(modpack),
                "modpackVersion": json_opt(modpack_version),
                "gameType":       game_type,
            })
        })
        .collect();

    serde_json::to_vec(&entries).unwrap_or_else(|_| b"[]".to_vec())
}

fn motd_clone(cfg: Option<&kojacoord_config::ServerEntry>) -> String {
    cfg.and_then(|e| e.motd.clone()).unwrap_or_default()
}

fn json_opt(value: Option<String>) -> serde_json::Value {
    match value {
        Some(v) => serde_json::Value::String(v),
        None => serde_json::Value::Null,
    }
}

async fn measure_ping(addr: std::net::SocketAddr) -> Option<Duration> {
    let start = Instant::now();
    match tokio::time::timeout(PING_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Some(start.elapsed()),
        _ => None,
    }
}

pub fn parse_connect_payload(data: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(data).ok()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_predicates() {
        assert!(is_serverlist_channel(CHANNEL_SERVERLIST_MODERN));
        assert!(is_serverlist_channel(CHANNEL_SERVERLIST_LEGACY));
        assert!(is_connect_channel(CHANNEL_CONNECT_MODERN));
        assert!(is_connect_channel(CHANNEL_CONNECT_LEGACY));
        assert!(is_modpack_channel(CHANNEL_MODPACK_MODERN));
        assert!(!is_serverlist_channel("minecraft:brand"));
    }

    #[test]
    fn parse_connect_trims_and_rejects_empty() {
        assert_eq!(parse_connect_payload(b"lobby").as_deref(), Some("lobby"));
        assert_eq!(
            parse_connect_payload(b"  survival \n").as_deref(),
            Some("survival")
        );
        assert!(parse_connect_payload(b"").is_none());
        assert!(parse_connect_payload(b"   ").is_none());
    }
}
