use bytes::Bytes;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock, Semaphore};
use uuid::Uuid;

use crate::permissions::RoleRegistry;

use kojacoord_anticheat::AnticheatEngine;
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
    pub sessions: Arc<RwLock<HashMap<Uuid, SharedSession>>>,
    pub rsa_key: Arc<rsa::RsaPrivateKey>,
    pub http_client: reqwest::Client,
    pub session_semaphore: Arc<Semaphore>,
    pub routing: Arc<RoutingRules>,
    pub buffer_pool: Arc<BufferPool>,
    pub metrics: Arc<ProxyMetrics>,
    pub auth_pipeline_config: Arc<AuthPipelineConfig>,
    pub anticheat: Arc<AnticheatEngine>,

    pub db: Option<Arc<crate::db::Db>>,

    pub roles: Arc<RoleRegistry>,

    pub outbound: Arc<DashMap<Uuid, mpsc::UnboundedSender<Bytes>>>,

    pub started_at: std::time::Instant,

    pub cluster_coordinator: Option<Arc<ClusterCoordinator>>,
    pub service_discovery: Option<Arc<ServiceDiscovery>>,

    pub metrics_collector: Arc<MetricsCollector>,

    pub analytics: Arc<AnalyticsEngine>,

    pub plugin_manager: Arc<PluginManager>,

    pub tps_tracker: Arc<TpsTracker>,

    pub connection_throttle: Arc<ConnectionThrottle>,
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
            sessions: Arc::new(RwLock::new(HashMap::new())),
            rsa_key,
            http_client,
            session_semaphore,
            routing: Arc::new(RoutingRules::new(default_server)),
            buffer_pool: Arc::new(BufferPool::new()),
            metrics: Arc::new(ProxyMetrics::new()),
            auth_pipeline_config,
            anticheat,
            db,
            roles: Arc::new(roles),
            outbound: Arc::new(DashMap::new()),
            started_at: std::time::Instant::now(),
            cluster_coordinator,
            service_discovery,
            metrics_collector,
            analytics,
            plugin_manager,
            tps_tracker,
            connection_throttle,
        })
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
            let sessions = self.sessions.read().await;
            match sessions.get(uuid) {
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
            let sessions = self.sessions.read().await;
            match sessions.get(uuid) {
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
        let sessions = self.sessions.read().await;
        for (uuid, sess) in sessions.iter() {
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
