//! Server-driven cookies & cross-server transfers (1.20.5+).
//!
//! 1.20.5 added two related features: a key/value cookie store that
//! survives reconnects (server-set, client-stored) and a `Transfer`
//! packet that hands a client off to a different address without going
//! through the launcher's server-list flow. The proxy passes both
//! straight through — we don't tamper with cookie payloads or rewrite
//! transfer targets, since both are signed by the originating
//! backend.

use kojacoord_protocol::ProtocolVersion;

/// True for 1.20.5+ (proto 765+), where the cookie/transfer packets
/// exist on the wire. Pre-765 clients silently drop these packets, so
/// the relay needs to gate the passthrough on this.
pub fn supports_cookies_transfers(protocol_version: u32) -> bool {
    ProtocolVersion::from_id(protocol_version).id() >= 765
}

/// Per-session cookie cache. Lives on `PlayerSession` so the same
/// store survives across backend switches within a single client
/// connection (the whole point of cookies).
#[derive(Debug, Clone, Default)]
pub struct CookieStore {
    cookies: std::collections::HashMap<String, Vec<u8>>,
}

const MAX_COOKIE_STORE_SIZE: usize = 1024;
const MAX_COOKIE_DATA_SIZE: usize = 4096;

impl CookieStore {
    pub fn store(&mut self, key: String, data: Vec<u8>) {
        if data.len() > MAX_COOKIE_DATA_SIZE {
            tracing::warn!(key = %key, size = data.len(), "cookie data exceeds per-entry size limit, dropping");
            return;
        }
        if self.cookies.len() >= MAX_COOKIE_STORE_SIZE && !self.cookies.contains_key(&key) {
            if let Some(oldest_key) = self.cookies.keys().next().cloned() {
                self.cookies.remove(&oldest_key);
            }
        }
        self.cookies.insert(key, data);
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.cookies.get(key).cloned()
    }

    pub fn remove(&mut self, key: &str) {
        self.cookies.remove(key);
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }
}
