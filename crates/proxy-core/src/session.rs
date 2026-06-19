//! Per-player session state shared between connection / relay /
//! plugin event handlers.
//!
//! `SharedSession` is the `Arc<RwLock<PlayerSession>>` everything
//! reaches into when it needs the player's username, current backend,
//! protocol version, etc. The RwLock contention here is incidental —
//! most reads are `try_read()` from fan-out broadcast paths that
//! can skip a stuck session, and most writes are bounded to the
//! handshake / live-server-switch points.

use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::cookies_transfers::CookieStore;

/// Live mute state cached on the session so the relay can gate chat
/// without a database round-trip per message. `expires_at` is `None`
/// for a permanent mute. The relay treats an `expires_at` in the past
/// as expired (no longer muted).
#[derive(Debug, Clone)]
pub struct MuteState {
    pub reason: String,
    pub expires_at: Option<chrono::NaiveDateTime>,
}

impl MuteState {
    /// True if this mute is still in force at the current time.
    pub fn is_active(&self) -> bool {
        match self.expires_at {
            None => true,
            Some(exp) => exp > chrono::Utc::now().naive_utc(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Handshaking,
    Status,
    Login,
    Configuration,
    Play,
}

pub struct PlayerSession {
    pub uuid: Uuid,
    pub username: String,
    pub client_ip: IpAddr,
    pub protocol_version: u32,
    pub state: ConnectionState,
    pub current_server: Option<String>,
    pub transferred: bool,
    pub properties: Vec<kojacoord_auth::ProfileProperty>,
    pub locale: Option<String>,
    pub view_distance: Option<u8>,

    pub rank: String,
    pub cookies: CookieStore,

    /// Active chat mute, loaded at login and updated live by the HTTP
    /// API / sanction bridge. `None` means the player may chat freely.
    pub mute: Option<MuteState>,
}

pub type SharedSession = Arc<RwLock<PlayerSession>>;
