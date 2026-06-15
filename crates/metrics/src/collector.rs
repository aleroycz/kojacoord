//! Prometheus counters/gauges/histograms the proxy writes to from the
//! hot path. The exporter reads the same `Registry` when Prometheus
//! scrapes; each metric is typed so callers get a compile error if
//! they update the wrong one rather than silently dropping samples.

use prometheus::{Counter, CounterVec, Gauge, GaugeVec, Histogram, Registry};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

const LABEL_CARDINALITY_CAP: usize = 1000;

pub struct MetricsCollector {
    registry: Registry,

    connections_total: Counter,
    connections_active: Gauge,
    connections_by_protocol: CounterVec,

    packets_relayed: Counter,
    packets_dropped: Counter,
    packet_size_bytes: Histogram,

    request_duration: Histogram,
    relay_latency: Histogram,

    violations_total: CounterVec,
    violations_by_check: CounterVec,

    server_player_count: GaugeVec,
    server_status: GaugeVec,

    errors_total: CounterVec,

    label_cardinality: Mutex<HashMap<String, HashSet<String>>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        let registry = Registry::new();

        let connections_total =
            Counter::new("kojacoord_connections_total", "Total number of connections").unwrap();
        registry
            .register(Box::new(connections_total.clone()))
            .unwrap();

        let connections_active = Gauge::new(
            "kojacoord_connections_active",
            "Number of active connections",
        )
        .unwrap();
        registry
            .register(Box::new(connections_active.clone()))
            .unwrap();

        let connections_by_protocol = CounterVec::new(
            prometheus::opts!(
                "kojacoord_connections_by_protocol",
                "Connections by protocol version"
            ),
            &["protocol_version"],
        )
        .unwrap();
        registry
            .register(Box::new(connections_by_protocol.clone()))
            .unwrap();

        let packets_relayed =
            Counter::new("kojacoord_packets_relayed_total", "Total packets relayed").unwrap();
        registry
            .register(Box::new(packets_relayed.clone()))
            .unwrap();

        let packets_dropped =
            Counter::new("kojacoord_packets_dropped_total", "Total packets dropped").unwrap();
        registry
            .register(Box::new(packets_dropped.clone()))
            .unwrap();

        let packet_size_bytes = Histogram::with_opts(
            prometheus::HistogramOpts::new("kojacoord_packet_size_bytes", "Packet size in bytes")
                .buckets(vec![16.0, 64.0, 256.0, 1024.0, 4096.0, 16384.0]),
        )
        .unwrap();
        registry
            .register(Box::new(packet_size_bytes.clone()))
            .unwrap();

        let request_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "kojacoord_request_duration_seconds",
                "Request duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
        )
        .unwrap();
        registry
            .register(Box::new(request_duration.clone()))
            .unwrap();

        let relay_latency = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "kojacoord_relay_latency_seconds",
                "Packet relay latency in seconds",
            )
            .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05]),
        )
        .unwrap();
        registry.register(Box::new(relay_latency.clone())).unwrap();

        let violations_total = CounterVec::new(
            prometheus::opts!("kojacoord_violations_total", "Total anti-cheat violations"),
            &["severity"],
        )
        .unwrap();
        registry
            .register(Box::new(violations_total.clone()))
            .unwrap();

        let violations_by_check = CounterVec::new(
            prometheus::opts!("kojacoord_violations_by_check", "Violations by check name"),
            &["check_name"],
        )
        .unwrap();
        registry
            .register(Box::new(violations_by_check.clone()))
            .unwrap();

        let server_player_count = GaugeVec::new(
            prometheus::opts!("kojacoord_server_player_count", "Player count per server"),
            &["server_name"],
        )
        .unwrap();
        registry
            .register(Box::new(server_player_count.clone()))
            .unwrap();

        let server_status = GaugeVec::new(
            prometheus::opts!(
                "kojacoord_server_status",
                "Server status (1=online, 0=offline)"
            ),
            &["server_name"],
        )
        .unwrap();
        registry.register(Box::new(server_status.clone())).unwrap();

        let errors_total = CounterVec::new(
            prometheus::opts!("kojacoord_errors_total", "Total errors"),
            &["error_type"],
        )
        .unwrap();
        registry.register(Box::new(errors_total.clone())).unwrap();

        Self {
            registry,
            connections_total,
            connections_active,
            connections_by_protocol,
            packets_relayed,
            packets_dropped,
            packet_size_bytes,
            request_duration,
            relay_latency,
            violations_total,
            violations_by_check,
            server_player_count,
            server_status,
            errors_total,
            label_cardinality: Mutex::new(HashMap::new()),
        }
    }

    fn sanitize_label(&self, metric: &str, value: &str) -> String {
        let mut map = self.label_cardinality.lock().unwrap();
        let seen = map.entry(metric.to_string()).or_default();
        if seen.contains(value) {
            return value.to_string();
        }
        if seen.len() >= LABEL_CARDINALITY_CAP {
            return "__other__".to_string();
        }
        let sanitized: String = value
            .chars()
            .take(64)
            .map(|c| {
                if c.is_alphanumeric() || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        seen.insert(sanitized.clone());
        sanitized
    }

    pub fn record_connection(&self, protocol_version: &str) {
        self.connections_total.inc();
        let label = self.sanitize_label("protocol_version", protocol_version);
        self.connections_by_protocol
            .with_label_values(&[&label])
            .inc();
        self.connections_active.inc();
    }

    pub fn record_disconnect(&self) {
        self.connections_active.dec();
    }

    pub fn record_packet(&self, size: usize) {
        self.packets_relayed.inc();
        self.packet_size_bytes.observe(size as f64);
    }

    pub fn record_packet_drop(&self) {
        self.packets_dropped.inc();
    }

    pub fn record_request_duration(&self, duration_seconds: f64) {
        self.request_duration.observe(duration_seconds);
    }

    pub fn record_relay_latency(&self, latency_seconds: f64) {
        self.relay_latency.observe(latency_seconds);
    }

    pub fn record_violation(&self, check_name: &str, severity: &str) {
        self.violations_total.with_label_values(&[severity]).inc();
        let label = self.sanitize_label("check_name", check_name);
        self.violations_by_check.with_label_values(&[&label]).inc();
    }

    pub fn set_server_player_count(&self, server_name: &str, count: usize) {
        let label = self.sanitize_label("server_name", server_name);
        self.server_player_count
            .with_label_values(&[&label])
            .set(count as f64);
    }

    pub fn set_server_status(&self, server_name: &str, online: bool) {
        let label = self.sanitize_label("server_name", server_name);
        self.server_status
            .with_label_values(&[&label])
            .set(if online { 1.0 } else { 0.0 });
    }

    pub fn record_error(&self, error_type: &str) {
        let label = self.sanitize_label("error_type", error_type);
        self.errors_total.with_label_values(&[&label]).inc();
    }

    pub fn get_registry(&self) -> &Registry {
        &self.registry
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
