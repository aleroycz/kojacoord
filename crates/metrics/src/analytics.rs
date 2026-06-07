use chrono::{DateTime, Timelike, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct AnalyticsEngine {
    hourly_buckets: Arc<DashMap<String, (u64, u64)>>, // (Joins, Leaves)
    total_players: AtomicU64,
    peak_players: AtomicU64,
    total_violations: AtomicU64,
    violations_by_type: Arc<DashMap<String, AtomicU64>>,
    start_time: DateTime<Utc>,
    retention_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    PlayerJoin,
    PlayerLeave,
    Violation,
    ServerStatusChange,
    ConnectionError,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsAggregates {
    pub total_players: u64,
    pub peak_players: u64,
    pub total_violations: u64,
    pub violations_by_type: HashMap<String, u64>,
    pub uptime_seconds: u64,
    pub start_time: DateTime<Utc>,
}

impl AnalyticsEngine {
    pub fn new(retention_hours: u64) -> Self {
        Self {
            hourly_buckets: Arc::new(DashMap::new()),
            total_players: AtomicU64::new(0),
            peak_players: AtomicU64::new(0),
            total_violations: AtomicU64::new(0),
            violations_by_type: Arc::new(DashMap::new()),
            start_time: Utc::now(),
            retention_hours,
        }
    }

    pub async fn record_event(&self, event: AnalyticsEvent) {
        let hour_key = event.timestamp.format("%Y-%m-%d-%H").to_string();

        let mut entry = self.hourly_buckets.entry(hour_key).or_insert((0, 0));

        match &event.event_type {
            EventType::PlayerJoin => {
                entry.0 += 1;
                let current = self.total_players.fetch_add(1, Ordering::Relaxed) + 1;
                self.peak_players.fetch_max(current, Ordering::Relaxed);
            },
            EventType::PlayerLeave => {
                entry.1 += 1;
                self.total_players.fetch_sub(1, Ordering::Relaxed); // Assumes we don't underflow
            },
            EventType::Violation => {
                self.total_violations.fetch_add(1, Ordering::Relaxed);
                if let Some(check_name) = event.data.get("check_name").and_then(|v| v.as_str()) {
                    let counter = self
                        .violations_by_type
                        .entry(check_name.to_string())
                        .or_insert_with(|| AtomicU64::new(0));
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            },
            _ => {},
        }
        drop(entry);

        // Cleanup old buckets (roughly by checking keys)
        let cutoff = Utc::now() - chrono::Duration::hours(self.retention_hours as i64);
        let cutoff_str = cutoff.format("%Y-%m-%d-%H").to_string();
        self.hourly_buckets.retain(|k, _| *k >= cutoff_str);
    }

    pub async fn get_aggregates(&self) -> AnalyticsAggregates {
        let uptime_seconds = (Utc::now() - self.start_time).num_seconds() as u64;
        let mut violations = HashMap::new();
        for ref_kv in self.violations_by_type.iter() {
            violations.insert(ref_kv.key().clone(), ref_kv.value().load(Ordering::Relaxed));
        }

        AnalyticsAggregates {
            total_players: self.total_players.load(Ordering::Relaxed),
            peak_players: self.peak_players.load(Ordering::Relaxed),
            total_violations: self.total_violations.load(Ordering::Relaxed),
            violations_by_type: violations,
            uptime_seconds,
            start_time: self.start_time,
        }
    }

    pub async fn get_violation_stats(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        for ref_kv in self.violations_by_type.iter() {
            stats.insert(ref_kv.key().clone(), ref_kv.value().load(Ordering::Relaxed));
        }
        stats
    }

    pub async fn get_player_history(&self, hours: u64) -> Vec<(DateTime<Utc>, u64)> {
        let mut history = Vec::new();
        let now = Utc::now();

        for i in 0..hours {
            let hour_time = now - chrono::Duration::hours(i as i64);
            let hour_key = hour_time.format("%Y-%m-%d-%H").to_string();

            let mut joins = 0;
            let mut leaves = 0;
            if let Some(entry) = self.hourly_buckets.get(&hour_key) {
                joins = entry.0;
                leaves = entry.1;
            }

            let hour_start = hour_time
                .date_naive()
                .and_hms_opt(hour_time.hour(), 0, 0)
                .unwrap();
            let hour_start_utc = DateTime::from_naive_utc_and_offset(hour_start, Utc);

            history.push((hour_start_utc, joins.saturating_sub(leaves)));
        }

        history.reverse();
        history
    }
}

impl Default for AnalyticsEngine {
    fn default() -> Self {
        Self::new(24)
    }
}
