//! Token-bucket connection throttle with auto temp-ban.
//!
//! Two layers: per-IP buckets (the usual case) and per-ASN buckets
//! (defended for whole networks behind a single shared NAT). Each
//! bucket refills at a fixed rate; when it empties, the source gets
//! a temporary ban that expires on its own. ASN lookup is a hook —
//! the default impl returns `None` so ASN throttling is effectively
//! off unless operators wire in a GeoLite reader.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// New connections allowed per IP before a temporary ban.
/// Default tuned to tolerate shared/CGNAT addresses; operators
/// can override via `proxy.max_connections_per_ip`. `0` disables throttling.
const DEFAULT_MAX_CONNECTIONS_PER_IP: u32 = 8;
const REFILL_RATE_PER_SEC: f32 = 2.0;
const CAPACITY: f32 = 8.0;
const TEMP_BAN_DURATION: Duration = Duration::from_secs(120);
const MAX_IP_RECORDS: usize = 1_000_000;
const MAX_ASN_RECORDS: usize = 100_000;

/// New connections allowed per ASN before a temporary ban.
/// Default tuned to tolerate large networks; operators
/// can override via `proxy.max_connections_per_asn`. `0` disables throttling.
const DEFAULT_MAX_CONNECTIONS_PER_ASN: u32 = 64;
const ASN_REFILL_RATE_PER_SEC: f32 = 4.0;
const ASN_CAPACITY: f32 = 64.0;
const ASN_TEMP_BAN_DURATION: Duration = Duration::from_secs(300);

#[derive(Debug)]
struct IpRecord {
    tokens: f32,
    last_update: Instant,
    banned_until: Option<Instant>,
}

#[derive(Debug)]
struct AsnRecord {
    tokens: f32,
    last_update: Instant,
    banned_until: Option<Instant>,
}

/// Per-IP and per-ASN token-bucket throttle with automatic temp-ban on exhaustion.
#[derive(Clone, Debug)]
pub struct ConnectionThrottle {
    ip_records: Arc<Mutex<HashMap<IpAddr, IpRecord>>>,
    asn_records: Arc<Mutex<HashMap<u32, AsnRecord>>>,
    max_per_ip: u32,
    max_per_asn: u32,
}

impl Default for ConnectionThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionThrottle {
    pub fn new() -> Self {
        Self::with_limits(
            DEFAULT_MAX_CONNECTIONS_PER_IP,
            DEFAULT_MAX_CONNECTIONS_PER_ASN,
        )
    }

    /// Build a throttle with custom per-IP and per-ASN limits.
    /// A value of `0` disables throttling for that dimension.
    pub fn with_limits(max_per_ip: u32, max_per_asn: u32) -> Self {
        Self {
            ip_records: Arc::new(Mutex::new(HashMap::new())),
            asn_records: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
            max_per_asn,
        }
    }

    /// Check if a connection from the given IP should be allowed.
    /// This checks both IP-level and ASN-level throttling.
    pub async fn check(&self, ip: IpAddr) -> Result<(), &'static str> {
        // Check IP-level throttling
        if self.max_per_ip > 0 {
            self.check_ip(ip).await?
        }

        // Check ASN-level throttling (if enabled)
        if self.max_per_asn > 0 {
            let asn = self.resolve_asn(ip).await;
            if let Some(asn) = asn {
                self.check_asn(asn).await?
            }
        }

        Ok(())
    }

    async fn check_ip(&self, ip: IpAddr) -> Result<(), &'static str> {
        let mut map = self.ip_records.lock().await;
        let now = Instant::now();

        if !map.contains_key(&ip) && map.len() >= MAX_IP_RECORDS {
            let now_snapshot = now;
            map.retain(|_, rec| {
                let active = rec.banned_until.is_some_and(|u| now_snapshot < u);
                let not_full = rec.tokens < CAPACITY;
                let recent = now_snapshot.duration_since(rec.last_update) < Duration::from_secs(10);
                active || not_full || recent
            });
            if map.len() >= MAX_IP_RECORDS {
                tracing::warn!(
                    "connection_throttle: IP records at capacity ({MAX_IP_RECORDS}), dropping new IP"
                );
                return Err("too many connections from IP");
            }
        }

        let rec = map.entry(ip).or_insert_with(|| IpRecord {
            tokens: CAPACITY,
            last_update: now,
            banned_until: None,
        });

        if let Some(until) = rec.banned_until {
            if now < until {
                tracing::warn!(%ip, "throttle: rejecting temp-banned IP");
                return Err("temporarily banned by IP");
            }
            rec.banned_until = None;
            rec.tokens = CAPACITY;
        }

        let elapsed = now.duration_since(rec.last_update).as_secs_f32();
        rec.tokens = (rec.tokens + elapsed * REFILL_RATE_PER_SEC).min(CAPACITY);
        rec.last_update = now;

        if rec.tokens < 1.0 {
            rec.banned_until = Some(now + TEMP_BAN_DURATION);
            tracing::warn!(%ip, "throttle: IP token bucket empty — temp-banning");
            return Err("too many connections from IP");
        }

        rec.tokens -= 1.0;
        Ok(())
    }

    async fn check_asn(&self, asn: u32) -> Result<(), &'static str> {
        let mut map = self.asn_records.lock().await;
        let now = Instant::now();

        if !map.contains_key(&asn) && map.len() >= MAX_ASN_RECORDS {
            let now_snapshot = now;
            map.retain(|_, rec| {
                let active = rec.banned_until.is_some_and(|u| now_snapshot < u);
                let not_full = rec.tokens < ASN_CAPACITY;
                let recent = now_snapshot.duration_since(rec.last_update) < Duration::from_secs(30);
                active || not_full || recent
            });
            if map.len() >= MAX_ASN_RECORDS {
                tracing::warn!(
                    "connection_throttle: ASN records at capacity ({MAX_ASN_RECORDS}), dropping new ASN"
                );
                return Err("too many connections from ASN");
            }
        }

        let rec = map.entry(asn).or_insert_with(|| AsnRecord {
            tokens: ASN_CAPACITY,
            last_update: now,
            banned_until: None,
        });

        if let Some(until) = rec.banned_until {
            if now < until {
                tracing::warn!(asn, "throttle: rejecting temp-banned ASN");
                return Err("temporarily banned by ASN");
            }
            rec.banned_until = None;
            rec.tokens = ASN_CAPACITY;
        }

        let elapsed = now.duration_since(rec.last_update).as_secs_f32();
        rec.tokens = (rec.tokens + elapsed * ASN_REFILL_RATE_PER_SEC).min(ASN_CAPACITY);
        rec.last_update = now;

        if rec.tokens < 1.0 {
            rec.banned_until = Some(now + ASN_TEMP_BAN_DURATION);
            tracing::warn!(asn, "throttle: ASN token bucket empty — temp-banning");
            return Err("too many connections from ASN");
        }

        rec.tokens -= 1.0;
        Ok(())
    }

    /// Resolve the ASN for an IP address.
    ///
    /// This intentionally returns `None`: the proxy has no built-in ASN
    /// dataset, and we don't want to bake a network call into the accept
    /// path. Operators that need ASN-level throttling should plug in a
    /// MaxMind GeoLite2 reader (or similar) here and return the looked-up
    /// origin AS number. While this returns `None`, the per-IP bucket above
    /// is the only active layer of throttling.
    async fn resolve_asn(&self, _ip: IpAddr) -> Option<u32> {
        None
    }

    /// Evict stale records to prevent memory bloat.
    pub async fn evict_stale(&self) {
        let now = Instant::now();

        // Evict stale IP records
        {
            let mut map = self.ip_records.lock().await;
            map.retain(|_, rec| {
                let active = rec.banned_until.is_some_and(|u| now < u);
                let not_full = rec.tokens < CAPACITY;
                let recent = now.duration_since(rec.last_update) < Duration::from_secs(10);
                active || not_full || recent
            });
        }

        // Evict stale ASN records
        {
            let mut map = self.asn_records.lock().await;
            map.retain(|_, rec| {
                let active = rec.banned_until.is_some_and(|u| now < u);
                let not_full = rec.tokens < ASN_CAPACITY;
                let recent = now.duration_since(rec.last_update) < Duration::from_secs(30);
                active || not_full || recent
            });
        }
    }
}
