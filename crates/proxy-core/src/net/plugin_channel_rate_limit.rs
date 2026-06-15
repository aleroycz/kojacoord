//! Rate limiting for plugin channel messages (chat, commands, etc.) to prevent spam.
//!
//! Uses a token-bucket algorithm per player to limit the rate of plugin channel
//! messages. Messages exceeding the rate limit are dropped with a warning log.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Default rate limit: 10 messages per second per player.
const DEFAULT_MESSAGES_PER_SECOND: f32 = 10.0;
const BURST_CAPACITY: f32 = 20.0;
const MAX_RATE_LIMIT_RECORDS: usize = 100_000;

#[derive(Debug)]
struct PlayerRateLimit {
    tokens: f32,
    last_update: Instant,
}

/// Rate limiter for plugin channel messages per player.
#[derive(Clone, Debug)]
pub struct PluginChannelRateLimiter {
    records: Arc<Mutex<HashMap<Uuid, PlayerRateLimit>>>,
    messages_per_second: f32,
}

impl Default for PluginChannelRateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_MESSAGES_PER_SECOND)
    }
}

impl PluginChannelRateLimiter {
    pub fn new(messages_per_second: f32) -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
            messages_per_second,
        }
    }

    /// Check if a plugin channel message from the given player should be allowed.
    /// Returns true if allowed, false if rate-limited.
    pub async fn check(&self, player_uuid: Uuid) -> bool {
        let mut map = self.records.lock().await;
        let now = Instant::now();

        if !map.contains_key(&player_uuid) && map.len() >= MAX_RATE_LIMIT_RECORDS {
            let now_snapshot = now;
            map.retain(|_, rec| {
                let not_full = rec.tokens < BURST_CAPACITY;
                let recent = now_snapshot.duration_since(rec.last_update) < Duration::from_secs(60);
                not_full || recent
            });
            if map.len() >= MAX_RATE_LIMIT_RECORDS {
                tracing::warn!(
                    "plugin_channel_rate_limit: records at capacity ({MAX_RATE_LIMIT_RECORDS}), rate-limiting new player"
                );
                return false;
            }
        }

        let rec = map.entry(player_uuid).or_insert_with(|| PlayerRateLimit {
            tokens: BURST_CAPACITY,
            last_update: now,
        });

        let elapsed = now.duration_since(rec.last_update).as_secs_f32();
        rec.tokens = (rec.tokens + elapsed * self.messages_per_second).min(BURST_CAPACITY);
        rec.last_update = now;

        if rec.tokens < 1.0 {
            tracing::warn!(
                player_uuid = %player_uuid,
                "Plugin channel message rate-limited (dropping)"
            );
            false
        } else {
            rec.tokens -= 1.0;
            true
        }
    }

    /// Evict stale records to prevent memory bloat.
    pub async fn evict_stale(&self) {
        let mut map = self.records.lock().await;
        let now = Instant::now();
        map.retain(|_, rec| {
            let not_full = rec.tokens < BURST_CAPACITY;
            let recent = now.duration_since(rec.last_update) < Duration::from_secs(60);
            not_full || recent
        });
    }

    /// Remove a player's rate limit record (e.g., on disconnect).
    pub async fn remove_player(&self, player_uuid: Uuid) {
        let mut map = self.records.lock().await;
        map.remove(&player_uuid);
    }
}
