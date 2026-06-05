use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// New connections allowed per IP within [`CONNECTION_WINDOW`] before a
/// temporary ban. Default tuned to tolerate shared/CGNAT addresses; operators
/// can override via `proxy.max_connections_per_ip`. `0` disables throttling.
const DEFAULT_MAX_CONNECTIONS_PER_IP: u32 = 8;
const CONNECTION_WINDOW: Duration = Duration::from_secs(3);
const TEMP_BAN_DURATION: Duration = Duration::from_secs(120);

#[derive(Debug)]
struct IpRecord {
    count: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
}

#[derive(Clone, Debug)]
pub struct ConnectionThrottle {
    records: Arc<Mutex<HashMap<IpAddr, IpRecord>>>,
    max_per_ip: u32,
}

impl Default for ConnectionThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionThrottle {
    pub fn new() -> Self {
        Self::with_max_per_ip(DEFAULT_MAX_CONNECTIONS_PER_IP)
    }

    /// Build a throttle with a custom per-IP limit. A value of `0` disables
    /// throttling entirely (every connection is allowed).
    pub fn with_max_per_ip(max_per_ip: u32) -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
        }
    }

    pub async fn check(&self, ip: IpAddr) -> Result<(), &'static str> {
        if self.max_per_ip == 0 {
            return Ok(());
        }

        let mut map = self.records.lock().await;
        let now = Instant::now();

        let rec = map.entry(ip).or_insert_with(|| IpRecord {
            count: 0,
            window_start: now,
            banned_until: None,
        });

        if let Some(until) = rec.banned_until {
            if now < until {
                tracing::warn!(%ip, "throttle: rejecting temp-banned IP");
                return Err("temporarily banned");
            }
            rec.banned_until = None;
        }

        if now.duration_since(rec.window_start) >= CONNECTION_WINDOW {
            rec.count = 0;
            rec.window_start = now;
        }

        rec.count += 1;

        if rec.count > self.max_per_ip {
            rec.banned_until = Some(now + TEMP_BAN_DURATION);
            tracing::warn!(
                %ip,
                count = rec.count,
                "throttle: too many connections — temp-banning"
            );
            return Err("too many connections");
        }

        Ok(())
    }

    pub async fn evict_stale(&self) {
        let mut map = self.records.lock().await;
        let now = Instant::now();
        map.retain(|_, rec| {
            rec.banned_until.is_some_and(|u| now < u)
                || now.duration_since(rec.window_start) < CONNECTION_WINDOW * 2
        });
    }
}
