//! Proxy state, listener, and background workers.
//!
//! [`ProxyState`] is the long-lived `Arc`-shared bag of "everything a
//! connection might need" — config, server registry, plugin manager,
//! databases, metrics, the lot. [`accept_loop`] binds the listening
//! socket, dispatches one `ClientConnection` per TCP accept, and
//! spawns the per-process background tasks (cached status refresh,
//! TPS sampling, throttle/rate-limit eviction, failover monitor,
//! HTTP/gRPC servers).
//!
//! Everything in here runs as long as the proxy does. Per-session
//! state lives on `PlayerSession`; per-connection state lives on
//! `ClientConnection` in `net::connection`.

use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};
use uuid::Uuid;

use crate::permissions::RoleRegistry;

use kojacoord_auth::{AuthConfig, AuthPipelineConfig};
use kojacoord_cluster::{ClusterCoordinator, ServiceDiscovery};
use kojacoord_config::ProxyConfig;
use kojacoord_metrics::{AnalyticsEngine, MetricsCollector, MetricsExporter};
use kojacoord_plugin_system::{PluginCommand, PluginEvent, PluginManager, PluginResponse};

use crate::buffer_pool::BufferPool;
use crate::connection_throttle::ConnectionThrottle;
use crate::control_plane::{ControlPlaneConfig, ControlPlaneServer, ControlPlaneState};
use crate::failover::FailoverManager;
use crate::health_probe::start_health_probes;
use crate::metrics::ProxyMetrics;
use crate::metrics_player::PlayerMetricsRegistry;
use crate::net::converter::chunk_repack::ChunkRepacker;
use crate::net::plugin_channel_rate_limit::PluginChannelRateLimiter;
use crate::protocol::ProtocolCoverage;
use crate::routing::RoutingRules;
use crate::security::EncryptionManager;
use crate::server::ServerRegistry;
use crate::server_management::ServerManagementServer;
use crate::session::SharedSession;

/// Lock-free TPS tracker using a fixed-size ring buffer of atomic timestamps.
///
/// The old design used `RwLock<Vec<Instant>>` with a write lock on every packet,
/// followed by a linear retain(). This caused severe contention in the relay hot
/// path — the root cause of the TPS degradation reported in production.
///
/// This replacement uses a ring buffer of `AtomicU64` slots holding microsecond
/// offsets from a fixed epoch. `record_packet()` is a single `fetch_add` + store
/// — zero locks, zero allocations, O(1). `calculate_tps()` does a lock-free scan
/// of the ring and counts entries within the requested window.
pub struct TpsTracker {
    /// Ring buffer of timestamps as microsecond offsets from `epoch`.
    slots: Box<[std::sync::atomic::AtomicU64]>,
    /// Write cursor — monotonically increasing, modulo `slots.len()`.
    cursor: std::sync::atomic::AtomicUsize,
    /// Fixed reference point for converting `Instant` → u64.
    epoch: Instant,
}

/// Sentinel value meaning "slot is empty / not yet written".
const EMPTY_SLOT: u64 = 0;

/// Ring buffer capacity. 32768 slots ≈ enough for 30s at 1000 pkt/s.
const RING_SIZE: usize = 32768;

impl TpsTracker {
    pub fn new() -> Self {
        let slots: Vec<std::sync::atomic::AtomicU64> = (0..RING_SIZE)
            .map(|_| std::sync::atomic::AtomicU64::new(EMPTY_SLOT))
            .collect();
        Self {
            slots: slots.into_boxed_slice(),
            cursor: std::sync::atomic::AtomicUsize::new(0),
            epoch: Instant::now(),
        }
    }

    /// Record a packet arrival. This is called on EVERY S→C packet in the relay
    /// hot path, so it must be as cheap as possible — one atomic add, one atomic
    /// store, no locks, no allocations.
    #[inline]
    pub fn record_packet(&self) {
        let idx = self
            .cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % RING_SIZE;
        let micros = self.epoch.elapsed().as_micros() as u64;
        // Avoid writing the sentinel value (extremely unlikely, only at t=0).
        let val = if micros == EMPTY_SLOT { 1 } else { micros };
        self.slots[idx].store(val, std::sync::atomic::Ordering::Relaxed);
    }

    /// Count packets within the last `window_seconds` and compute TPS.
    /// This is only called on `/tps` command — not on the hot path — so a full
    /// scan of the ring is fine.
    pub fn calculate_tps(&self, window_seconds: u64) -> f64 {
        let now_micros = self.epoch.elapsed().as_micros() as u64;
        let window_micros = window_seconds * 1_000_000;
        let cutoff = now_micros.saturating_sub(window_micros);

        let mut count = 0u64;
        for slot in self.slots.iter() {
            let val = slot.load(std::sync::atomic::Ordering::Relaxed);
            if val != EMPTY_SLOT && val >= cutoff {
                count += 1;
            }
        }

        if count == 0 {
            return 20.0;
        }

        count as f64 / window_seconds as f64
    }
}

impl Default for TpsTracker {
    fn default() -> Self {
        Self::new()
    }
}

type HotReloadMessage = (
    std::path::PathBuf,
    std::collections::HashMap<String, String>,
);
type HotReloadReceiver = tokio::sync::mpsc::UnboundedReceiver<HotReloadMessage>;

pub struct ProxyState {
    pub config: Arc<ProxyConfig>,
    pub server_registry: Arc<ServerRegistry>,
    pub sessions: Arc<DashMap<Uuid, SharedSession>>,
    pub rsa_key: Arc<rsa::RsaPrivateKey>,
    pub http_client: reqwest::Client,
    pub session_semaphore: Arc<Semaphore>,
    pub routing: Arc<RoutingRules>,
    pub buffer_pool: Arc<BufferPool>,
    pub metrics: Arc<ProxyMetrics>,
    pub auth_pipeline_config: Arc<AuthPipelineConfig>,
    pub db: Option<Arc<crate::db::Db>>,

    pub roles: Arc<RoleRegistry>,

    pub outbound: Arc<DashMap<Uuid, mpsc::UnboundedSender<Bytes>>>,
    pub backend_outbound: Arc<DashMap<Uuid, mpsc::UnboundedSender<Bytes>>>,

    pub started_at: std::time::Instant,

    pub cluster_coordinator: Option<Arc<ClusterCoordinator>>,
    pub service_discovery: Option<Arc<ServiceDiscovery>>,

    pub metrics_collector: Arc<MetricsCollector>,

    pub analytics: Arc<AnalyticsEngine>,

    /// Wrapped in `std::sync::RwLock` for performance in the hot path (packet hooks).
    /// The hot-reload watcher uses a channel-based approach to avoid holding locks
    /// across await points.
    pub plugin_manager: Arc<std::sync::RwLock<PluginManager>>,

    /// Plugin hot-reload channel. The watcher task (started by
    /// `start_plugin_hot_reload_watcher`) sends `(path, config)` tuples
    /// here; the processor task (started by the same call) drains them
    /// and applies the reload off the runtime worker via
    /// `spawn_blocking`. Stored on state so that other components
    /// (e.g. the HTTP management API) can also request a reload.
    pub hot_reload_tx: tokio::sync::mpsc::UnboundedSender<(
        std::path::PathBuf,
        std::collections::HashMap<String, String>,
    )>,
    /// Receiver side of `hot_reload_tx`, parked inside an option so the
    /// processor can `take()` it on startup. Wrapped in `std::sync::Mutex`
    /// because this is only touched once during boot.
    hot_reload_rx: std::sync::Mutex<Option<HotReloadReceiver>>,

    pub tps_tracker: Arc<TpsTracker>,

    pub connection_throttle: Arc<ConnectionThrottle>,

    /// Rate limiter for plugin channel messages (chat, commands, etc.)
    pub plugin_channel_rate_limiter: Arc<PluginChannelRateLimiter>,

    /// Per-player metrics and packet trace registry
    pub player_metrics: Arc<PlayerMetricsRegistry>,

    /// Failover manager for active-passive backend groups
    pub failover_manager: Arc<FailoverManager>,

    /// Broadcast trigger for graceful shutdown. Every connection task
    /// (handshake, login, limbo, relay) watches this and gets a wake
    /// the moment the proxy starts shutting down. Receivers then
    /// flush a Disconnect packet with the proxy's restart message and
    /// drop the socket cleanly — without it, players see "End of
    /// stream" instead of the configured shutdown reason.
    ///
    /// `tokio::sync::Notify` is chosen over a broadcast channel
    /// because we don't need to carry any payload — the reason
    /// string is identical for every kick and lives in
    /// `shutdown_reason` below. Notified tasks read that field.
    ///
    /// Polled via `shutdown_notify.notified()` inside `tokio::select!`
    /// branches alongside the normal I/O futures.
    pub shutdown_notify: Arc<tokio::sync::Notify>,

    /// Disconnect reason JSON to send during graceful shutdown. Set
    /// once at startup; tasks read it after `shutdown_notify` fires.
    pub shutdown_reason: Arc<arc_swap::ArcSwap<String>>,

    /// Pre-built JSON suffix for status responses, regenerated every second.
    pub cached_status: arc_swap::ArcSwap<CachedStatus>,

    /// Protocol coverage tracker for converter management
    pub protocol_coverage: Arc<ProtocolCoverage>,

    /// Chunk repacker for cross-version chunk data conversion
    pub chunk_repacker: Arc<ChunkRepacker>,

    /// Encryption manager for pluggable encryption algorithms
    pub encryption_manager: Arc<EncryptionManager>,

    /// gRPC control plane state for external orchestration
    pub control_plane_state: Arc<ControlPlaneState>,

    /// gRPC control plane server instance
    pub control_plane_server: Option<Arc<tokio::sync::Mutex<ControlPlaneServer>>>,
}

/// Snapshot of the status-response JSON suffix (players + description).
pub struct CachedStatus {
    pub suffix: String,
}

impl ProxyState {
    pub async fn new(config: ProxyConfig) -> Result<Self, anyhow::Error> {
        let rsa_key = Arc::new(kojacoord_auth::encryption::generate_rsa_keypair()?);
        let registry = Arc::new(ServerRegistry::new());

        for s in &config.servers {
            let addr: std::net::SocketAddr = s
                .address
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid server address {}: {}", s.address, e))?;
            registry
                .register(crate::server::BackendServer {
                    name: s.name.clone(),
                    address: addr,
                    restricted: s.restricted,
                    forwarding_override: s.forwarding_override.clone(),
                    player_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    online: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                    connection_pool: None,
                    backend_type: s.backend_type.clone(),
                    compression_threshold: s.compression_threshold,
                    cipher_suites: s.cipher_suites.clone(),
                    health_probe_interval_secs: s.health_probe_interval_secs,
                    health_probe_timeout_secs: s.health_probe_timeout_secs,
                    health_probe_fail_threshold: s.health_probe_fail_threshold,
                    health_fail_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                    health_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    region: s.region.clone(),
                })
                .await;
        }

        let default_server = config
            .servers
            .first()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "lobby".to_owned());

        let session_semaphore = Arc::new(Semaphore::new(600));

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let auth_config = AuthConfig {
            online_mode: config.proxy.online_mode,
            compression_threshold: config.proxy.compression_threshold,
            session_timeout_secs: config.proxy.session_timeout_secs,
            prevent_proxy_connections: config.proxy.prevent_proxy_connections,
            auth_type: kojacoord_auth::AuthType::Mojang,
        };

        let auth_pipeline_config = Arc::new(AuthPipelineConfig::new(
            Arc::clone(&rsa_key),
            http_client.clone(),
            Arc::clone(&session_semaphore),
            auth_config,
        )?);

        let db = if config.database.url.trim().is_empty() {
            let sqlite_path = "data/proxy.db";
            tracing::info!("No MySQL URL configured — using SQLite at {}", sqlite_path);
            // sqlx won't create missing parent directories, and the
            // default config ships with `data/` relative; ensure it
            // exists so first-run installs don't fail with
            // "unable to open database file".
            if let Some(parent) = std::path::Path::new(sqlite_path).parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        tracing::warn!(
                            error = %e,
                            path = %parent.display(),
                            "Failed to create SQLite parent directory"
                        );
                    }
                }
            }
            match crate::data::db::Db::connect_sqlite(sqlite_path).await {
                Ok(db) => {
                    tracing::info!("Connected to SQLite database");
                    Some(Arc::new(db))
                },
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to connect to SQLite — running without persistence");
                    None
                },
            }
        } else {
            match crate::data::db::Db::connect(
                &config.database.url,
                config.database.max_connections,
            )
            .await
            {
                Ok(db) => {
                    tracing::info!("Connected to MySQL database");
                    Some(Arc::new(db))
                },
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to connect to MySQL — running without persistence");
                    None
                },
            }
        };

        let roles = match &db {
            Some(db) => match db.load_roles().await {
                Ok(rows) if !rows.is_empty() => {
                    tracing::info!(count = rows.len(), "Loaded roles from database");
                    RoleRegistry::from_rows(rows)
                },
                Ok(_) => {
                    tracing::warn!("No roles in database — using built-in default");
                    RoleRegistry::builtin_default()
                },
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to load roles — using built-in default");
                    RoleRegistry::builtin_default()
                },
            },
            None => RoleRegistry::builtin_default(),
        };

        let (cluster_coordinator, service_discovery) = if config.cluster.enabled {
            let local_node_id = Uuid::new_v4();
            let discovery = Arc::new(ServiceDiscovery::new(local_node_id));

            let coordinator = Arc::new(ClusterCoordinator::new(
                Arc::clone(&discovery),
                local_node_id,
            ));

            let local_address: std::net::SocketAddr = config
                .cluster
                .node_address
                .parse()
                .unwrap_or_else(|_| "0.0.0.0:25565".parse().unwrap());

            if let Err(e) = coordinator
                .initialize(local_address, config.cluster.max_players)
                .await
            {
                tracing::warn!(error = %e, "Failed to initialize cluster coordinator");
            }

            let heartbeat_coord = Arc::clone(&coordinator);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    if let Err(e) = heartbeat_coord.elect_leader().await {
                        tracing::warn!(error = %e, "Cluster heartbeat / leader election failed");
                    }
                }
            });

            (Some(coordinator), Some(discovery))
        } else {
            (None, None)
        };

        let metrics_collector = Arc::new(MetricsCollector::new());
        let analytics = Arc::new(AnalyticsEngine::new(config.metrics.retention_hours));

        let plugin_manager = if config.plugins.enabled {
            let mut manager = PluginManager::new().context("Failed to create plugin manager")?;

            // Set allowed permissions from config
            for (plugin_name, perm_strings) in &config.plugin_permissions {
                let permissions: Vec<kojacoord_plugin_system::api::PluginPermission> = perm_strings
                    .iter()
                    .filter_map(|s| {
                        serde_json::from_str::<kojacoord_plugin_system::api::PluginPermission>(
                            format!("\"{}\"", s).as_str(),
                        )
                        .ok()
                    })
                    .collect();
                manager.set_allowed_permissions(plugin_name.clone(), permissions);
            }

            if !config.plugins.plugin_dir.is_empty() {
                let plugin_dir = &config.plugins.plugin_dir;
                let configs = config.plugins.configs.clone();

                if let Err(e) = manager.load_plugins_from_dir(plugin_dir, configs).await {
                    tracing::warn!(error = %e, "Failed to load plugins from directory");
                }
            }

            Arc::new(std::sync::RwLock::new(manager))
        } else {
            Arc::new(std::sync::RwLock::new(
                PluginManager::new().context("Failed to create plugin manager")?,
            ))
        };

        let tps_tracker = Arc::new(TpsTracker::new());

        let connection_throttle = Arc::new(ConnectionThrottle::with_limits(
            config.proxy.max_connections_per_ip,
            0,
        ));

        let plugin_channel_rate_limiter = Arc::new(PluginChannelRateLimiter::default());

        let player_metrics = Arc::new(PlayerMetricsRegistry::new(1000)); // Store up to 1000 trace entries per player

        let failover_manager = Arc::new(FailoverManager::new(Arc::clone(&registry)));

        // Load failover groups from config
        failover_manager
            .load_groups(config.failover_groups.clone())
            .await;

        // Initialize new components
        let protocol_coverage = Arc::new(ProtocolCoverage::new());
        tracing::info!("Protocol coverage tracker initialized");

        let chunk_repacker = Arc::new(ChunkRepacker::new());
        tracing::info!("Chunk repacker initialized");

        let encryption_manager = Arc::new(EncryptionManager::new());
        tracing::info!(
            "Encryption manager initialized with algorithms: {:?}",
            encryption_manager.registered_algorithms()
        );

        let control_plane_state = Arc::new(ControlPlaneState::new());
        tracing::info!("gRPC control plane state initialized");

        if config.metrics.enabled {
            let exporter = MetricsExporter::new(Arc::clone(&metrics_collector));
            let bind = config.metrics.bind.clone();
            tokio::spawn(async move {
                if let Err(e) = exporter.serve(bind).await {
                    tracing::error!(error = %e, "Metrics exporter stopped");
                }
            });
            tracing::info!("Metrics exporter started on {}", config.metrics.bind);
        }

        // Build the plugin hot-reload channel. The watcher writes here;
        // `start_plugin_hot_reload_watcher` will `take()` the receiver from
        // `hot_reload_rx` and drive it.
        let (hot_reload_tx, hot_reload_rx) = tokio::sync::mpsc::unbounded_channel::<(
            std::path::PathBuf,
            std::collections::HashMap<String, String>,
        )>();

        let route_rules: Vec<crate::routing::RouteRule> = config
            .routing
            .rules
            .iter()
            .map(|r| crate::routing::RouteRule {
                label: r.label.clone(),
                name_glob: r.name_glob.clone(),
                client_cidrs: r.client_cidrs.clone(),
                target: r.target.clone(),
            })
            .collect();

        Ok(Self {
            config: Arc::new(config),
            server_registry: registry,
            sessions: Arc::new(DashMap::new()),
            rsa_key,
            http_client,
            session_semaphore,
            routing: Arc::new(RoutingRules::with_rules(default_server, route_rules)),
            buffer_pool: Arc::new(BufferPool::new()),
            metrics: Arc::new(ProxyMetrics::new()),
            auth_pipeline_config,
            db,
            roles: Arc::new(roles),
            outbound: Arc::new(DashMap::new()),
            backend_outbound: Arc::new(DashMap::new()),
            started_at: std::time::Instant::now(),
            cluster_coordinator,
            service_discovery,
            metrics_collector,
            analytics,
            plugin_manager,
            hot_reload_tx,
            hot_reload_rx: std::sync::Mutex::new(Some(hot_reload_rx)),
            tps_tracker,
            connection_throttle,
            plugin_channel_rate_limiter,
            player_metrics,
            failover_manager,
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
            shutdown_reason: Arc::new(arc_swap::ArcSwap::new(Arc::new(
                r#"{"text":"Proxy is restarting, Please try again later.","color":"yellow"}"#
                    .to_string(),
            ))),
            cached_status: arc_swap::ArcSwap::new(Arc::new(CachedStatus {
                suffix:
                    r#"},"players":{"max":0,"online":0,"sample":[]},"description":{"text":""}}"#
                        .to_string(),
            })),
            protocol_coverage,
            chunk_repacker,
            encryption_manager,
            control_plane_state,
            control_plane_server: None,
        })
    }

    /// Hot-reload the server registry when the config file changes on disk.
    pub async fn reload_servers(&self, new_config: &kojacoord_config::ProxyConfig) {
        let mut new_names = std::collections::HashSet::new();
        for s in &new_config.servers {
            new_names.insert(s.name.clone());
            let addr = match s.address.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(name = %s.name, address = %s.address, error = %e, "Invalid server address in config, skipping");
                    continue;
                },
            };

            if let Some(existing) = self.server_registry.get(&s.name) {
                let needs_update = existing.address != addr
                    || existing.restricted != s.restricted
                    || existing.forwarding_override != s.forwarding_override
                    || existing.backend_type != s.backend_type;

                if needs_update {
                    let old_player_count = existing
                        .player_count
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let old_online = existing.online.load(std::sync::atomic::Ordering::Relaxed);

                    self.server_registry
                        .register(crate::server::BackendServer {
                            name: s.name.clone(),
                            address: addr,
                            restricted: s.restricted,
                            forwarding_override: s.forwarding_override.clone(),
                            player_count: Arc::new(std::sync::atomic::AtomicUsize::new(
                                old_player_count,
                            )),
                            online: Arc::new(std::sync::atomic::AtomicBool::new(old_online)),
                            connection_pool: None,
                            backend_type: s.backend_type.clone(),
                            compression_threshold: s.compression_threshold,
                            cipher_suites: s.cipher_suites.clone(),
                            health_probe_interval_secs: s.health_probe_interval_secs,
                            health_probe_timeout_secs: s.health_probe_timeout_secs,
                            health_probe_fail_threshold: s.health_probe_fail_threshold,
                            health_fail_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                            health_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                            region: s.region.clone(),
                        })
                        .await;
                    tracing::info!("Hot-reloaded (updated) server: {}", s.name);
                }
            } else {
                self.server_registry
                    .register(crate::server::BackendServer {
                        name: s.name.clone(),
                        address: addr,
                        restricted: s.restricted,
                        forwarding_override: s.forwarding_override.clone(),
                        player_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                        online: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                        connection_pool: None,
                        backend_type: s.backend_type.clone(),
                        compression_threshold: s.compression_threshold,
                        cipher_suites: s.cipher_suites.clone(),
                        health_probe_interval_secs: s.health_probe_interval_secs,
                        health_probe_timeout_secs: s.health_probe_timeout_secs,
                        health_probe_fail_threshold: s.health_probe_fail_threshold,
                        health_fail_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                        health_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                        region: s.region.clone(),
                    })
                    .await;
                tracing::info!("Hot-reloaded new server: {}", s.name);
            }
        }

        let all_current = self.server_registry.all();
        for current in all_current {
            if !new_names.contains(&current.name) {
                self.server_registry.remove(&current.name);
                tracing::info!("Hot-reloaded (removed) server: {}", current.name);
            }
        }
    }

    /// Hot-reload everything that can be swapped in-place without rebuilding
    /// `ProxyState`. Called when the on-disk config changes or (on Unix) on
    /// SIGHUP.
    ///
    /// Server registry entries and the cached status suffix (MOTD + max
    /// players) live behind `DashMap`/`ArcSwap` and can be mutated freely.
    /// Routing rules and the top-level `ProxyConfig` are stored as `Arc<…>`
    /// with no interior mutability — swapping them in-place would require
    /// `ArcSwap` everywhere they're read, so for now we log that those
    /// require a restart.
    pub async fn reload_config(&self, new_config: &kojacoord_config::ProxyConfig) {
        tracing::info!("Hot-reloading configuration...");

        // MOTD lives in `listeners.motd` (string) or `listeners.motd_json`
        // (full JSON component). Rebuild the cached status suffix.
        let motd = &new_config.listeners.motd;
        let new_suffix = format!(
            r#"}},"players":{{"max":{},"online":0,"sample":[]}},"description":{{"text":{}}}}}"#,
            new_config.proxy.max_players,
            serde_json::to_string(motd).unwrap_or_else(|_| "\"A Minecraft Server\"".into()),
        );
        self.cached_status
            .store(Arc::new(CachedStatus { suffix: new_suffix }));
        tracing::info!("Hot-reloaded MOTD / max players");

        self.reload_servers(new_config).await;

        // Routing rules and the rest of ProxyConfig are immutable in this
        // build — they're stored as `Arc<ProxyConfig>` read straight from
        // the hot path. Swapping them in place would require routing every
        // access through `ArcSwap`; that's a follow-up. For now: note that
        // those parts require a restart.
        let _ = new_config; // suppress unused-when-only-routing-changed warning
        tracing::info!(
            "Routing/forwarding/auth changes require a restart; servers + MOTD reloaded live"
        );

        tracing::info!("Configuration hot-reload complete");
    }

    pub fn send_to_player(&self, uuid: &Uuid, packet: Bytes) -> bool {
        if let Some(tx) = self.outbound.get(uuid) {
            tx.send(packet).is_ok()
        } else {
            false
        }
    }

    /// Pick a backend for a connecting player, threading the choice
    /// through the failover manager.
    ///
    /// The flow:
    ///   1. `RoutingRules::select_with_region` returns the routing-rule
    ///      candidate. (Lobby-by-region rules win over default.)
    ///   2. If that candidate belongs to a failover group, swap it for
    ///      the group's currently-active backend. The failover
    ///      monitor flips that field whenever the primary goes down,
    ///      so step 2 keeps routing in sync with health probes.
    ///   3. If the swapped-in backend is offline (rare — usually means
    ///      ALL standbys in the group are down too), keep the original
    ///      candidate and let the upstream connect attempt surface the
    ///      error. That's a better failure mode than silently routing
    ///      to a different group entirely.
    ///
    /// Returns `None` only if the registry has no servers at all — at
    /// which point the proxy would have logged a startup error and the
    /// caller will drop into limbo.
    pub async fn route_via_failover(
        &self,
        client_ip: Option<std::net::IpAddr>,
    ) -> Option<Arc<crate::server::BackendServer>> {
        let candidate = self
            .routing
            .select_with_region(&self.server_registry, client_ip)?;

        // Walk the failover map once to find the group (if any) this
        // candidate participates in; ask the manager for that group's
        // current_active; swap if it differs and the new pick is up.
        if let Some(group) = self
            .failover_manager
            .get_group_for_server(candidate.name.as_str())
            .await
        {
            if let Some(active_name) = self.failover_manager.get_active_server(&group).await {
                if active_name != candidate.name {
                    if let Some(active) = self.server_registry.get(&active_name) {
                        if active.is_online() {
                            tracing::debug!(
                                group = %group,
                                original = %candidate.name,
                                active = %active_name,
                                "Failover-aware routing: candidate replaced with current_active",
                            );
                            return Some(active);
                        }
                    }
                }
            }
        }
        Some(candidate)
    }

    /// Graceful shutdown: kick every connected player with the same
    /// "Proxy is restarting" message, give the writers a brief grace
    /// window to flush the disconnect packet to the socket, then
    /// return so the runtime can drop the listener.
    ///
    /// Triggered from any exit code path — Ctrl+C, SIGTERM, panic
    /// inside the accept loop, etc. — by wiring this through a single
    /// shutdown future at the top level (see `main.rs`).
    ///
    /// Without this the OS just rips the sockets out, the client sees
    /// "Connection reset" and has to retry blindly. With it, the
    /// client sees a textual reason and knows to try again in a few
    /// seconds.
    pub async fn shutdown_gracefully(&self, reason_json: &str) {
        let total = self.sessions.len();
        tracing::warn!(
            sessions = total,
            "Graceful shutdown: notifying every connected player"
        );

        // Publish the reason so every connection task picks up the
        // same text, then notify them all at once. Each task is
        // responsible for writing its own Disconnect packet because
        // only the task knows the right wire format (pre-netty vs
        // modern, compression threshold, current state — Login vs
        // Play vs Configuration). This is the only correct way to
        // kick a player who's still in the login/limbo phase, since
        // those connections have no entry in `self.outbound`.
        self.shutdown_reason
            .store(Arc::new(reason_json.to_string()));
        self.shutdown_notify.notify_waiters();

        // Best-effort outbound channel push for any player who DID
        // make it past limbo into the relay phase — the relay's
        // notify watcher will also write a disconnect, but pushing
        // through `outbound` covers the case where the writer is
        // currently parked on the queue and not on a `select!`.
        let uuids: Vec<Uuid> = self.sessions.iter().map(|e| *e.key()).collect();
        for uuid in &uuids {
            self.kick_player(uuid, reason_json).await;
        }

        // Drain window: tasks need time to flush their socket buffer
        // before we let the runtime shut down. 1500ms is enough for
        // a TCP write+flush+FIN on any healthy socket; failing
        // sockets get the RST path within the same window.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        // Players are out — now unload plugins. Order matters: we
        // wait until the connection tasks have flushed their
        // disconnect packets BEFORE we tear down plugins, because
        // plugins may be holding plugin-channel registrations the
        // s2c disconnect flush would otherwise route through. Once
        // sockets are closed the plugins have no live connections
        // left to serve and can shut down cleanly.
        //
        // `unload_all` calls each plugin's `on_disable` → `on_unload`
        // in sequence; we hold the write lock through the whole
        // sweep so no late `dispatch_plugin_event` can race against
        // an already-disabled plugin.
        {
            let mut mgr = self
                .plugin_manager
                .write()
                .unwrap_or_else(|e| e.into_inner());
            tracing::warn!("Graceful shutdown: calling on_disable / on_unload on all plugins");
            mgr.unload_all();
        }
        tracing::warn!(notified = total, "Graceful shutdown notification complete");
    }

    pub async fn kick_player(&self, uuid: &Uuid, reason_json: &str) {
        let proto = {
            match self.sessions.get(uuid) {
                Some(s) => s.try_read().map(|s| s.protocol_version).ok(),
                None => None,
            }
        };
        if let Some(proto) = proto {
            let pkt = crate::packet_builder::build_disconnect_packet(reason_json, proto);
            self.send_to_player(uuid, pkt);
        }
    }

    /// Send a system chat message to a single player by UUID.
    pub async fn send_system_message_to(&self, uuid: &Uuid, text: &str) {
        let proto = {
            match self.sessions.get(uuid) {
                Some(s) => s.try_read().map(|s| s.protocol_version).ok(),
                None => None,
            }
        };
        if let Some(proto) = proto {
            let raw = crate::packet_builder::build_system_message_packet(text, proto);
            self.send_to_player(uuid, raw);
        }
    }

    /// Deliver a [`PluginEvent`] to all loaded plugins and act on their
    /// responses (broadcast / direct message / kick). Returns `true` if the
    /// event's subject player was kicked by a plugin, so the caller can stop
    /// processing that connection.
    pub async fn dispatch_plugin_event(&self, event: PluginEvent) -> bool {
        let subject = match &event {
            PluginEvent::PlayerJoin { uuid, .. }
            | PluginEvent::PlayerChat { uuid, .. }
            | PluginEvent::PlayerLeave { uuid }
            | PluginEvent::PlayerMove { uuid, .. } => Some(*uuid),
            _ => None,
        };

        // broadcast_event locks each plugin only for the duration of its
        // handler and returns owned responses, so no plugin lock is held across
        // the awaits below.
        let responses = self
            .plugin_manager
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .broadcast_event(&event);

        let mut subject_kicked = false;
        for response in responses {
            match response {
                PluginResponse::None => {},
                PluginResponse::Message(msg) => {
                    if let Some(uuid) = subject {
                        self.send_system_message_to(&uuid, &msg).await;
                    }
                },
                PluginResponse::Broadcast(msg) => self.broadcast_system_message(&msg).await,
                PluginResponse::KickPlayer { uuid, reason } => {
                    let json = serde_json::json!({ "text": reason, "color": "red" }).to_string();
                    self.kick_player(&uuid, &json).await;
                    if Some(uuid) == subject {
                        subject_kicked = true;
                    }
                },
                PluginResponse::Custom(value) => {
                    tracing::debug!(?value, "plugin returned a custom response");
                },
                PluginResponse::Cancel => {
                    // Event cancellation is handled inside `broadcast_event`
                    // (which short-circuits propagation). Nothing to do at
                    // the dispatcher layer.
                },
                PluginResponse::UpdatePlayerSample { .. } => {
                    // Player-sample updates are only meaningful for the
                    // ServerListPing event and are consumed by the status
                    // handler directly. Ignore here.
                },
            }
        }
        subject_kicked
    }

    pub async fn broadcast_system_message(&self, text: &str) {
        for entry in self.sessions.iter() {
            let uuid = entry.key();
            let sess = entry.value();
            let proto = match sess.try_read() {
                Ok(s) => s.protocol_version,
                Err(_) => continue,
            };
            let raw = crate::packet_builder::build_system_message_packet(text, proto);
            self.send_to_player(uuid, raw);
        }
    }

    /// Spawn background tasks that listen to each loaded plugin's command
    /// channel and execute the requested privileged operations.
    pub fn start_plugin_command_processors(self: &Arc<Self>) {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            let mut handles = vec![];
            let receivers = {
                let mgr = state
                    .plugin_manager
                    .read()
                    .unwrap_or_else(|e| e.into_inner());
                let mut lock = mgr
                    .command_receivers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                std::mem::take(&mut *lock)
            };
            for (name, mut rx) in receivers {
                let state_clone = Arc::clone(&state);
                let name_clone = name.clone();
                let handle = tokio::spawn(async move {
                    while let Some(cmd) = rx.recv().await {
                        state_clone.process_plugin_command(&name_clone, cmd).await;
                    }
                    tracing::info!("Plugin command channel closed for {}", name_clone);
                });
                handles.push(handle);
            }
            for h in handles {
                let _ = h.await;
            }
        });
    }

    /// Watch the configured plugins directory for new or modified plugin artifacts and enqueue reloads.
    ///
    /// Spawns two background tasks: a poll-based directory watcher that detects changes to files with
    /// extensions `dll`, `so`, `dylib`, `kpl`, or `wasm` and a processor that applies reloads on a
    /// blocking thread. The function returns immediately and is a no-op when hot-reload is disabled,
    /// the plugin directory is unset, or the watcher has already been started.
    ///
    /// # Examples
    ///
    /// ```
    /// // Assuming `state: std::sync::Arc<ProxyState>` is initialized and plugin hot-reload is enabled:
    /// state.start_plugin_hot_reload_watcher();
    /// ```
    pub fn start_plugin_hot_reload_watcher(self: &Arc<Self>) {
        if !self.config.plugins.enabled || !self.config.plugins.hot_reload {
            return;
        }
        let dir = self.config.plugins.plugin_dir.clone();
        if dir.is_empty() {
            return;
        }
        let interval_secs = self.config.plugins.hot_reload_interval_secs.max(1);

        // Take ownership of the rx that was minted in `ProxyState::new`. If
        // this function is called twice (it shouldn't be) the second call
        // is a no-op rather than a panic.
        let rx = match self
            .hot_reload_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            Some(rx) => rx,
            None => {
                tracing::warn!("hot-reload watcher already started; ignoring second start");
                return;
            },
        };

        // ── watcher ────────────────────────────────────────────────
        let watcher_state = Arc::clone(self);
        let watcher_dir = dir.clone();
        tokio::spawn(async move {
            let dir_path = std::path::PathBuf::from(&watcher_dir);
            let mut mtimes: std::collections::HashMap<std::path::PathBuf, std::time::SystemTime> =
                std::collections::HashMap::new();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            // Skip the first immediate tick — record file mtimes once on
            // startup as the baseline; only changes after launch trigger
            // reloads.
            interval.tick().await;
            tracing::info!(
                dir = %watcher_dir,
                interval_secs,
                "hot-reload watcher active"
            );
            loop {
                interval.tick().await;
                let mut entries = match tokio::fs::read_dir(&dir_path).await {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::trace!(error = %e, "hot-reload: read_dir failed");
                        continue;
                    },
                };
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    let is_plugin = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|ext| {
                            matches!(
                                ext.to_ascii_lowercase().as_str(),
                                "dll" | "so" | "dylib" | "kpl" | "wasm"
                            )
                        });
                    if !is_plugin {
                        continue;
                    }
                    let Ok(meta) = entry.metadata().await else {
                        continue;
                    };
                    let Ok(mtime) = meta.modified() else { continue };
                    let prev = mtimes.insert(path.clone(), mtime);
                    let changed = matches!(prev, Some(p) if p != mtime);
                    if !changed {
                        continue;
                    }
                    let plugin_name = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let cfg = watcher_state
                        .config
                        .plugins
                        .configs
                        .get(&plugin_name)
                        .cloned()
                        .unwrap_or_default();
                    tracing::info!(
                        plugin = %plugin_name,
                        path = %path.display(),
                        "hot-reload: change detected, queueing reload"
                    );
                    let _ = watcher_state.hot_reload_tx.send((path, cfg));
                }
            }
        });

        // ── processor ──────────────────────────────────────────────
        let proc_state = Arc::clone(self);
        let mut rx = rx;
        tokio::spawn(async move {
            while let Some((path, cfg)) = rx.recv().await {
                let plugin_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                tracing::info!(
                    plugin = %plugin_name,
                    path = %path.display(),
                    "hot-reload: processing reload request"
                );
                // The plugin manager is a `std::sync::RwLock` (kept that
                // way for hot-path performance — every relayed packet
                // takes a read guard). The guard contains a wasmtime
                // `MutexGuard` which is `!Send`, so we can't hold the
                // write lock across `reload_plugin`'s await points.
                // Drive the reload on a blocking thread with its own
                // current-thread runtime.
                let state_for_reload = Arc::clone(&proc_state);
                let path_for_reload = path.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut mgr = state_for_reload
                        .plugin_manager
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("build single-thread runtime for plugin reload");
                    rt.block_on(mgr.reload_plugin(&path_for_reload, cfg))
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("reload task panicked: {e}")));
                match result {
                    Ok(meta) => tracing::info!(
                        plugin = %plugin_name,
                        version = %meta.version,
                        "hot-reload: plugin reloaded"
                    ),
                    Err(e) => tracing::warn!(
                        plugin = %plugin_name,
                        error = %e,
                        "hot-reload: reload failed"
                    ),
                }
            }
        });
    }

    /// Start the gRPC control plane server if enabled
    pub fn start_grpc_control_plane(self: &Arc<Self>) {
        if !self.config.grpc_control_plane.enabled {
            tracing::info!("gRPC control plane disabled in config, skipping");
            return;
        }

        let state = Arc::clone(self);
        tokio::spawn(async move {
            let grpc_config = ControlPlaneConfig {
                bind_address: state.config.grpc_control_plane.bind_address.clone(),
                port: state.config.grpc_control_plane.port,
                tls_enabled: state.config.grpc_control_plane.tls_enabled,
                tls_cert_path: state.config.grpc_control_plane.tls_cert_path.clone(),
                tls_key_path: state.config.grpc_control_plane.tls_key_path.clone(),
                auth_enabled: state.config.grpc_control_plane.auth_enabled,
                auth_token: state.config.grpc_control_plane.auth_token.clone(),
            };

            let mut server =
                ControlPlaneServer::new(grpc_config, state.control_plane_state.clone());

            if let Err(e) = server.start().await {
                tracing::error!(error = %e, "Failed to start gRPC control plane");
            } else {
                tracing::info!(
                    "gRPC control plane started successfully on {}:{}",
                    state.config.grpc_control_plane.bind_address,
                    state.config.grpc_control_plane.port
                );
            }
        });
    }

    async fn process_plugin_command(&self, plugin_name: &str, cmd: PluginCommand) {
        match cmd {
            PluginCommand::RegisterServer {
                name,
                address,
                port,
                max_players: _,
            } => {
                let addr = match format!("{}:{}", address, port).parse::<std::net::SocketAddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::warn!(plugin = %plugin_name, name = %name, error = %e, "Plugin requested invalid server address");
                        return;
                    },
                };
                if self.server_registry.get(&name).is_some() {
                    self.server_registry.remove(&name);
                }
                let server = crate::server::BackendServer {
                    name: name.clone(),
                    address: addr,
                    restricted: false,
                    forwarding_override: None,
                    player_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    online: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                    connection_pool: None,
                    backend_type: kojacoord_config::BackendType::default(),
                    compression_threshold: 0,
                    cipher_suites: String::new(),
                    health_probe_interval_secs: 0,
                    health_probe_timeout_secs: 5,
                    health_probe_fail_threshold: 3,
                    health_fail_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                    health_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    region: String::new(),
                };
                self.server_registry.register(server).await;
                tracing::info!(plugin = %plugin_name, "Registered server {} at {}:{}", name, address, port);
            },
            PluginCommand::DeregisterServer { name } => {
                if self.server_registry.get(&name).is_some() {
                    let default_server = self
                        .config
                        .servers
                        .first()
                        .map(|s| s.name.clone())
                        .unwrap_or_else(|| "lobby".to_owned());
                    self.evacuate_players(&name, &default_server).await;
                    self.server_registry.remove(&name);
                    tracing::info!(plugin = %plugin_name, "Deregistered server {}", name);
                }
            },
            PluginCommand::TransferPlayer { uuid, server } => {
                if let Some(target) = self.sessions.get(&uuid) {
                    if let Some(old_name) = target.read().await.current_server.clone() {
                        if let Some(old) = self.server_registry.get(&old_name) {
                            old.player_count
                                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    if let Some(new_srv) = self.server_registry.get(&server) {
                        new_srv
                            .player_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    target.write().await.current_server = Some(server.clone());
                    tracing::info!(plugin = %plugin_name, "Transferred player {} to {}", uuid, server);
                }
            },
            PluginCommand::KickPlayer { uuid, reason } => {
                let json = serde_json::json!({ "text": reason }).to_string();
                self.kick_player(&uuid, &json).await;
                tracing::info!(plugin = %plugin_name, "Kicked player {}: {}", uuid, reason);
            },
            PluginCommand::SendSystemMessage { uuid, message } => {
                self.send_system_message_to(&uuid, &message).await;
            },
            PluginCommand::UpdatePlayerStatus {
                uuid,
                server,
                online,
            } => {
                if let Some(db) = &self.db {
                    let server_name = server.unwrap_or_default();
                    if let Err(e) = db.update_player_status(uuid, &server_name, online).await {
                        tracing::warn!(plugin = %plugin_name, error = %e, "Failed to update player status");
                    }
                }
            },
        }
    }

    /// Move all players currently on `from_server` to `to_server`.
    ///
    /// We snapshot `(uuid, SharedSession)` from the DashMap into a `Vec`
    /// up front and only then start awaiting. Iterating a DashMap holds
    /// per-shard guards, and `kick_player()` reaches back into the same
    /// `sessions` map — re-entering a held shard would deadlock. The
    /// snapshot is cheap (an `Arc` clone per session) and decouples the
    /// shard-lifetime from the await-lifetime.
    async fn evacuate_players(&self, from_server: &str, to_server: &str) -> usize {
        let snapshot: Vec<(Uuid, SharedSession)> = self
            .sessions
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect();

        let mut evacuated = 0usize;
        for (uuid, session) in snapshot {
            let current = {
                let s = session.read().await;
                s.current_server.clone()
            };
            if current.as_deref() == Some(from_server) {
                {
                    let mut s = session.write().await;
                    s.current_server = Some(to_server.to_owned());
                }
                if let Some(old) = self.server_registry.get(from_server) {
                    old.player_count
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
                if let Some(new_srv) = self.server_registry.get(to_server) {
                    new_srv
                        .player_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let reason = r#"{"text":"§cThe server you were on has shut down. Reconnecting you to the lobby..."}"#;
                self.kick_player(&uuid, reason).await;
                evacuated += 1;
            }
        }
        evacuated
    }
}

pub async fn accept_loop(state: Arc<ProxyState>) -> Result<(), anyhow::Error> {
    let bind_addr = state.config.proxy.bind.clone();
    let listener = TcpListener::bind(&bind_addr).await?;
    tracing::info!("KojacoordProxy listening on {}", bind_addr);

    if state.config.server_management.enabled {
        let mgmt_server = ServerManagementServer::new(
            Arc::clone(&state),
            state.config.server_management.bind.clone(),
            state.config.server_management.auth_token.clone(),
        );
        if let Err(e) = mgmt_server.spawn().await {
            tracing::error!("Failed to start server management TCP server: {}", e);
        } else {
            tracing::info!(
                "Server management TCP server started on {}",
                state.config.server_management.bind
            );
        }
    }

    if state.config.http_api.enabled {
        let api_state = Arc::clone(&state);
        let bind = state.config.http_api.bind.clone();
        let token = state.config.http_api.auth_token.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::http_api::serve(api_state, bind, token).await {
                tracing::error!(error = %e, "HTTP API server stopped");
            }
        });
    }

    // Start gRPC control plane if enabled
    state.start_grpc_control_plane();

    // Start modpack online counts background reporting loop
    crate::metrics_report::start_reporting(Arc::clone(&state));

    // Periodically evict stale per-IP throttle records so the map cannot grow
    // unbounded (e.g. from a wide IPv6 source range).
    tokio::spawn({
        let throttle = Arc::clone(&state.connection_throttle);
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                throttle.evict_stale().await;
            }
        }
    });

    // Periodically evict stale plugin channel rate limit records
    tokio::spawn({
        let rate_limiter = Arc::clone(&state.plugin_channel_rate_limiter);
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                rate_limiter.evict_stale().await;
            }
        }
    });

    // Periodically evict inactive player metrics
    tokio::spawn({
        let player_metrics = Arc::clone(&state.player_metrics);
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 minutes
            loop {
                interval.tick().await;
                player_metrics
                    .evict_inactive(std::time::Duration::from_secs(3600))
                    .await; // 1 hour timeout
            }
        }
    });

    // Start health probe task for backend servers
    start_health_probes(Arc::clone(&state.server_registry));

    // Start failover monitoring task
    Arc::clone(&state.failover_manager).start_monitoring();

    tokio::spawn({
        let metrics = Arc::clone(&state.metrics);
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let snapshot = metrics.snapshot();
                tracing::info!(
                    total = snapshot.total_connections,
                    active = snapshot.active_connections,
                    packets = snapshot.packets_relayed,
                    bytes = snapshot.bytes_transferred,
                    failed = snapshot.failed_connections,
                    "Metrics snapshot"
                );
            }
        }
    });

    // Refresh the cached status response every second so the MOTD and player
    // list shown to pingers stays up-to-date without blocking the accept loop.
    tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;

                let (online_count, sample) = {
                    let count = state.sessions.len();
                    let server_lore = &state.config.listeners.server_lore;

                    let mut sample: Vec<serde_json::Value> = state
                        .sessions
                        .iter()
                        .take(12)
                        .filter_map(|entry| {
                            let s = entry.value();
                            s.try_read().ok().map(|g| {
                                let mut player_json = serde_json::json!({
                                    "name": g.username,
                                    "id": g.uuid.hyphenated().to_string()
                                });
                                if let Some(lore) = server_lore {
                                    player_json["lore"] = serde_json::json!(lore);
                                }
                                player_json
                            })
                        })
                        .collect();

                    if sample.is_empty() {
                        if let Some(lore) = server_lore {
                            sample.push(serde_json::json!({
                                "name": "",
                                "id": "",
                                "lore": lore
                            }));
                        }
                    }

                    (count, sample)
                };

                let description = if let Some(ref motd_json) = state.config.listeners.motd_json {
                    motd_json.clone()
                } else {
                    serde_json::json!({ "text": &state.config.listeners.motd })
                };

                let players_json = serde_json::json!({
                    "max":    state.config.proxy.max_players,
                    "online": online_count,
                    "sample": sample,
                });

                let suffix = [
                    r#"},"players":"#,
                    &serde_json::to_string(&players_json).unwrap_or_else(|_| "{}".to_string()),
                    r#","description":"#,
                    &serde_json::to_string(&description).unwrap_or_else(|_| "{}".to_string()),
                    r#"}"#,
                ]
                .join("");

                state.cached_status.store(Arc::new(CachedStatus { suffix }));
            }
        }
    });

    tracing::info!("Accepting incoming connections...");
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let peer = peer_addr.to_string();

        // Connection-flood protection: reject (and temp-ban) IPs opening
        // connections faster than the configured per-IP rate before doing any
        // per-connection work.
        if let Err(reason) = state.connection_throttle.check(peer_addr.ip()).await {
            tracing::debug!(peer = %peer, reason, "throttled connection rejected");
            drop(stream);
            continue;
        }

        tracing::info!("New connection from {}", peer);

        if let Err(e) = stream.set_nodelay(true) {
            tracing::warn!(peer = %peer, error = %e, "Failed to set TCP_NODELAY");
        }

        tracing::debug!(peer = %peer, "Connection established with optimized TCP settings");

        let state = Arc::clone(&state);
        state.metrics.record_connection();

        tokio::spawn(async move {
            let conn =
                crate::connection::ClientConnection::new(stream, peer_addr, Arc::clone(&state));
            match conn.run().await {
                Ok(()) => {
                    tracing::info!("Connection {} closed successfully", peer);
                },
                Err(e) => {
                    let msg = e.to_string();
                    tracing::warn!("Connection {} ended with error: {}", peer, msg);
                    state.metrics.record_failed_connection();
                },
            }
            state.metrics.record_disconnection();
        });
    }
}
