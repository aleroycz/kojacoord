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
}

pub type SharedSession = Arc<RwLock<PlayerSession>>;
