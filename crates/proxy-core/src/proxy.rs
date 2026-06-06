use bytes::Bytes;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock, Semaphore};
use uuid::Uuid;

use crate::permissions::RoleRegistry;

use kojacoord_anticheat::{AnticheatEngine, XrayEngine};
use kojacoord_auth::{AuthConfig, AuthPipelineConfig};
use kojacoord_cluster::{ClusterCoordinator, ServiceDiscovery};
use kojacoord_config::ProxyConfig;
use kojacoord_metrics::{AnalyticsEngine, MetricsCollector, MetricsExporter};
use kojacoord_plugin_system::{PluginEvent, PluginManager, PluginResponse};

use crate::buffer_pool::BufferPool;
use crate::connection_throttle::ConnectionThrottle;
use crate::metrics::ProxyMetrics;
use crate::routing::RoutingRules;
use crate::server::ServerRegistry;
use crate::server_management::ServerManagementServer;
use crate::session::SharedSession;

#[derive(Clone)]
pub struct TpsTracker {
    packet_timestamps: Arc<RwLock<Vec<Instant>>>,
}

impl TpsTracker {
    pub fn new() -> Self {
        Self {
            packet_timestamps: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn record_packet(&self) {
        let mut timestamps = self.packet_timestamps.write().await;
        timestamps.push(Instant::now());

        let cutoff = Instant::now() - Duration::from_secs(30);
        timestamps.retain(|&t| t > cutoff);
    }

    pub async fn calculate_tps(&self, window_seconds: u64) -> f64 {
        let timestamps = self.packet_timestamps.read().await;
        let cutoff = Instant::now() - Duration::from_secs(window_seconds);

        let count = timestamps.iter().filter(|&&t| t > cutoff).count();
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
    pub anticheat: Arc<AnticheatEngine>,
    /// Author : Starfloof.
    pub xray: Arc<XrayEngine>,

    pub db: Option<Arc<crate::db::Db>>,

    pub roles: Arc<RoleRegistry>,

    pub outbound: Arc<DashMap<Uuid, mpsc::UnboundedSender<Bytes>>>,
    pub backend_outbound: Arc<DashMap<Uuid, mpsc::UnboundedSender<Bytes>>>,

    pub started_at: std::time::Instant,

    pub cluster_coordinator: Option<Arc<ClusterCoordinator>>,
    pub service_discovery: Option<Arc<ServiceDiscovery>>,

    pub metrics_collector: Arc<MetricsCollector>,

    pub analytics: Arc<AnalyticsEngine>,

    pub plugin_manager: Arc<PluginManager>,

    pub tps_tracker: Arc<TpsTracker>,

    pub connection_throttle: Arc<ConnectionThrottle>,

    /// Author : Starfloof.
    pub cached_status: arc_swap::ArcSwap<CachedStatus>,
}

/// Author : Starfloof.
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

        let anticheat = Arc::new(AnticheatEngine::new(config.anticheat.clone()));
        // XRay honeypot engine — enabled whenever anticheat is enabled.
        let xray = Arc::new(XrayEngine::new(config.anticheat.enabled, None));

        let db = if config.database.url.trim().is_empty() {
            let sqlite_path = "data/proxy.db";
            tracing::info!("No MySQL URL configured — using SQLite at {}", sqlite_path);
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
            let mut manager = PluginManager::new();

            if !config.plugins.plugin_dir.is_empty() {
                let plugin_dir = &config.plugins.plugin_dir;
                let configs = config.plugins.configs.clone();

                if let Err(e) = manager.load_plugins_from_dir(plugin_dir, configs) {
                    tracing::warn!(error = %e, "Failed to load plugins from directory");
                }
            }

            Arc::new(manager)
        } else {
            Arc::new(PluginManager::new())
        };

        let tps_tracker = Arc::new(TpsTracker::new());

        let connection_throttle = Arc::new(ConnectionThrottle::with_max_per_ip(
            config.proxy.max_connections_per_ip,
        ));

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

        Ok(Self {
            config: Arc::new(config),
            server_registry: registry,
            sessions: Arc::new(DashMap::new()),
            rsa_key,
            http_client,
            session_semaphore,
            routing: Arc::new(RoutingRules::new(default_server)),
            buffer_pool: Arc::new(BufferPool::new()),
            metrics: Arc::new(ProxyMetrics::new()),
            auth_pipeline_config,
            anticheat,
            xray,
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
            tps_tracker,
            connection_throttle,
            cached_status: arc_swap::ArcSwap::new(Arc::new(CachedStatus {
                suffix:
                    r#"},"players":{"max":0,"online":0,"sample":[]},"description":{"text":""}}"#
                        .to_string(),
            })),
        })
    }

    /// Author : Starfloof.
    pub async fn reload_servers(&self, new_config: &kojacoord_config::ProxyConfig) {
        let mut new_names = std::collections::HashSet::new();
        for s in &new_config.servers {
            new_names.insert(s.name.clone());
            let addr = match s.address.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(name = %s.name, address = %s.address, error = %e, "Invalid server address in config, skipping");
                    continue;
                }
            };

            if let Some(existing) = self.server_registry.get(&s.name) {
                let needs_update = existing.address != addr
                    || existing.restricted != s.restricted
                    || existing.forwarding_override != s.forwarding_override
                    || existing.backend_type != s.backend_type;

                if needs_update {
                    let old_player_count = existing.player_count.load(std::sync::atomic::Ordering::Relaxed);
                    let old_online = existing.online.load(std::sync::atomic::Ordering::Relaxed);

                    self.server_registry
                        .register(crate::server::BackendServer {
                            name: s.name.clone(),
                            address: addr,
                            restricted: s.restricted,
                            forwarding_override: s.forwarding_override.clone(),
                            player_count: Arc::new(std::sync::atomic::AtomicUsize::new(old_player_count)),
                            online: Arc::new(std::sync::atomic::AtomicBool::new(old_online)),
                            connection_pool: None,
                            backend_type: s.backend_type.clone(),
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

    pub fn send_to_player(&self, uuid: &Uuid, packet: Bytes) -> bool {
        if let Some(tx) = self.outbound.get(uuid) {
            tx.send(packet).is_ok()
        } else {
            false
        }
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
        let responses = self.plugin_manager.broadcast_event(&event);

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

    // Author : Starfloof.
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
