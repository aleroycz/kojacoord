use chrono::{DateTime, Timelike, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct AnalyticsEngine {
    hourly_buckets: Arc<DashMap<String, (u64, u64)>>, // (Joins, Leaves)
    aggregates: Arc<RwLock<AnalyticsAggregates>>,
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
            aggregates: Arc::new(RwLock::new(AnalyticsAggregates {
                total_players: 0,
                peak_players: 0,
                total_violations: 0,
                violations_by_type: HashMap::new(),
                uptime_seconds: 0,
                start_time: Utc::now(),
            })),
            retention_hours,
        }
    }

    pub async fn record_event(&self, event: AnalyticsEvent) {
        let hour_key = event.timestamp.format("%Y-%m-%d-%H").to_string();

        let mut aggregates = self.aggregates.write().await;
        let mut entry = self.hourly_buckets.entry(hour_key).or_insert((0, 0));

        match &event.event_type {
            EventType::PlayerJoin => {
                entry.0 += 1;
                aggregates.total_players += 1;
                if aggregates.total_players > aggregates.peak_players {
                    aggregates.peak_players = aggregates.total_players;
                }
            },
            EventType::PlayerLeave => {
                entry.1 += 1;
                aggregates.total_players = aggregates.total_players.saturating_sub(1);
            },
            EventType::Violation => {
                aggregates.total_violations += 1;
                if let Some(check_name) = event.data.get("check_name").and_then(|v| v.as_str()) {
                    *aggregates
                        .violations_by_type
                        .entry(check_name.to_string())
                        .or_insert(0) += 1;
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
        let mut aggregates = self.aggregates.write().await;
        aggregates.uptime_seconds = (Utc::now() - aggregates.start_time).num_seconds() as u64;
        aggregates.clone()
    }

    pub async fn get_violation_stats(&self) -> HashMap<String, u64> {
        let aggregates = self.aggregates.read().await;
        aggregates.violations_by_type.clone()
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
