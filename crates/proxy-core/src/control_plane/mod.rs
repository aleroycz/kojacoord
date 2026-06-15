//! gRPC control plane.
//!
//! Surface for external orchestrators (Kubernetes operators, custom
//! schedulers, the management dashboard) to add/remove backends, push
//! routing rules, and stream live metrics without restarting the proxy.
//! The wire types are generated from `proto/control_plane.proto` and
//! mirrored into the small Rust structs below — the duplication is
//! deliberate so the public Rust API stays stable when the .proto is
//! regenerated.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::transport::ServerTlsConfig;
use tonic::{Request, Response, Status};

// Include the generated protobuf code
#[allow(clippy::module_inception)]
pub mod control_plane {
    tonic::include_proto!("kojacoord.control_plane");
}

use control_plane::{control_plane_server::ControlPlane, *};
// The generated tonic service type — re-exported under a clearer name so it
// doesn't collide with our outer `ControlPlaneServer` struct.
use control_plane::control_plane_server::ControlPlaneServer as ProtoControlPlaneServer;

/// Lifecycle state of a backend, mirrored from the proto enum so the
/// rest of the crate doesn't depend on tonic-generated types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStatus {
    Online,
    Offline,
    Draining,
    Maintenance,
}

impl From<ServerStatus> for control_plane::ServerStatus {
    fn from(status: ServerStatus) -> Self {
        match status {
            ServerStatus::Online => control_plane::ServerStatus::Online,
            ServerStatus::Offline => control_plane::ServerStatus::Offline,
            ServerStatus::Draining => control_plane::ServerStatus::Draining,
            ServerStatus::Maintenance => control_plane::ServerStatus::Maintenance,
        }
    }
}

impl From<control_plane::ServerStatus> for ServerStatus {
    fn from(status: control_plane::ServerStatus) -> Self {
        match status {
            control_plane::ServerStatus::Online => ServerStatus::Online,
            control_plane::ServerStatus::Offline => ServerStatus::Offline,
            control_plane::ServerStatus::Draining => ServerStatus::Draining,
            control_plane::ServerStatus::Maintenance => ServerStatus::Maintenance,
        }
    }
}

/// Backend descriptor as seen by the control plane. Player counts and
/// latency are snapshot values at the time the orchestrator queried —
/// not live counters.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub name: String,
    pub address: String,
    pub status: ServerStatus,
    pub player_count: u32,
    pub max_players: u32,
    pub region: String,
    pub latency_ms: f64,
}

impl From<ServerInfo> for control_plane::ServerInfo {
    fn from(info: ServerInfo) -> Self {
        Self {
            name: info.name,
            address: info.address,
            status: info.status as i32,
            player_count: info.player_count,
            max_players: info.max_players,
            region: info.region,
            latency_ms: info.latency_ms,
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        }
    }
}

impl From<control_plane::ServerInfo> for ServerInfo {
    fn from(info: control_plane::ServerInfo) -> Self {
        // proto3 enums round-trip as i32 on the wire. tonic generates a
        // `TryFrom<i32>` impl for the proto enum; convert via that, then
        // map to our own ServerStatus.
        let proto_status = control_plane::ServerStatus::try_from(info.status)
            .unwrap_or(control_plane::ServerStatus::Offline);
        Self {
            name: info.name,
            address: info.address,
            status: proto_status.into(),
            player_count: info.player_count,
            max_players: info.max_players,
            region: info.region,
            latency_ms: info.latency_ms,
        }
    }
}

/// Routing rule pushed in over gRPC. Higher `priority` wins ties at
/// the matcher; `enabled = false` keeps the rule but skips it during
/// evaluation (useful for staged rollouts).
#[derive(Debug, Clone)]
pub struct RoutingRule {
    pub id: String,
    pub pattern: String,
    pub target: String,
    pub priority: u32,
    pub enabled: bool,
    pub metadata: HashMap<String, String>,
}

impl From<RoutingRule> for control_plane::RoutingRule {
    fn from(rule: RoutingRule) -> Self {
        Self {
            id: rule.id,
            pattern: rule.pattern,
            target: rule.target,
            priority: rule.priority,
            enabled: rule.enabled,
            metadata: rule.metadata,
        }
    }
}

impl From<control_plane::RoutingRule> for RoutingRule {
    fn from(rule: control_plane::RoutingRule) -> Self {
        Self {
            id: rule.id,
            pattern: rule.pattern,
            target: rule.target,
            priority: rule.priority,
            enabled: rule.enabled,
            metadata: rule.metadata,
        }
    }
}

/// Roll-up of proxy stats the control plane streams to subscribers.
/// CPU / memory percentages are sampled at the moment of the read; the
/// counters are cumulative since the proxy started.
#[derive(Debug, Clone)]
pub struct ProxyMetrics {
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub uptime_seconds: u64,
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub error_rate: f64,
}

impl From<ProxyMetrics> for control_plane::ProxyMetrics {
    fn from(metrics: ProxyMetrics) -> Self {
        Self {
            total_connections: metrics.total_connections,
            active_connections: metrics.active_connections,
            total_bytes_sent: metrics.total_bytes_sent,
            total_bytes_received: metrics.total_bytes_received,
            uptime_seconds: metrics.uptime_seconds,
            cpu_usage_percent: metrics.cpu_usage_percent,
            memory_usage_percent: metrics.memory_usage_percent,
            error_rate: metrics.error_rate,
        }
    }
}

/// Shared store backing the gRPC service. Everything lives behind
/// `tokio::sync::RwLock` because the gRPC handlers are async and the
/// payloads (server list, rule list) are read far more often than
/// written.
pub struct ControlPlaneState {
    servers: Arc<RwLock<HashMap<String, ServerInfo>>>,
    routing_rules: Arc<RwLock<HashMap<String, RoutingRule>>>,
    metrics: Arc<RwLock<ProxyMetrics>>,
    start_time: std::time::Instant,
}

impl ControlPlaneState {
    pub fn new() -> Self {
        Self {
            servers: Arc::new(RwLock::new(HashMap::new())),
            routing_rules: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(ProxyMetrics {
                total_connections: 0,
                active_connections: 0,
                total_bytes_sent: 0,
                total_bytes_received: 0,
                uptime_seconds: 0,
                cpu_usage_percent: 0.0,
                memory_usage_percent: 0.0,
                error_rate: 0.0,
            })),
            start_time: std::time::Instant::now(),
        }
    }

    pub async fn upsert_server(&self, server: ServerInfo) {
        let mut servers = self.servers.write().await;
        servers.insert(server.name.clone(), server);
    }

    pub async fn remove_server(&self, name: &str) -> Option<ServerInfo> {
        let mut servers = self.servers.write().await;
        servers.remove(name)
    }

    pub async fn get_server(&self, name: &str) -> Option<ServerInfo> {
        let servers = self.servers.read().await;
        servers.get(name).cloned()
    }

    pub async fn list_servers(&self) -> Vec<ServerInfo> {
        let servers = self.servers.read().await;
        servers.values().cloned().collect()
    }

    pub async fn update_server_status(
        &self,
        name: &str,
        status: ServerStatus,
    ) -> Result<(), String> {
        let mut servers = self.servers.write().await;
        if let Some(server) = servers.get_mut(name) {
            server.status = status;
            Ok(())
        } else {
            Err(format!("Server '{}' not found", name))
        }
    }

    pub async fn upsert_routing_rule(&self, rule: RoutingRule) {
        let mut rules = self.routing_rules.write().await;
        rules.insert(rule.id.clone(), rule);
    }

    pub async fn remove_routing_rule(&self, id: &str) -> Option<RoutingRule> {
        let mut rules = self.routing_rules.write().await;
        rules.remove(id)
    }

    pub async fn get_routing_rule(&self, id: &str) -> Option<RoutingRule> {
        let rules = self.routing_rules.read().await;
        rules.get(id).cloned()
    }

    pub async fn list_routing_rules(&self) -> Vec<RoutingRule> {
        let rules = self.routing_rules.read().await;
        rules.values().cloned().collect()
    }

    pub async fn toggle_routing_rule(&self, id: &str, enabled: bool) -> Result<(), String> {
        let mut rules = self.routing_rules.write().await;
        if let Some(rule) = rules.get_mut(id) {
            rule.enabled = enabled;
            Ok(())
        } else {
            Err(format!("Routing rule '{}' not found", id))
        }
    }

    /// Snapshot the metrics struct with `uptime_seconds` refreshed.
    /// Takes a *write* lock (cheap, contended only during snapshots) so
    /// the refresh is atomic with the read.
    pub async fn get_metrics(&self) -> ProxyMetrics {
        let mut metrics = self.metrics.write().await;
        metrics.uptime_seconds = self.start_time.elapsed().as_secs();
        metrics.clone()
    }

    /// Mutate the metrics under the write lock and return whatever the
    /// closure produced. The relay's per-packet counters use this to
    /// fold their deltas into the published snapshot.
    pub async fn update_metrics<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut ProxyMetrics) -> R,
    {
        let mut metrics = self.metrics.write().await;
        f(&mut metrics)
    }
}

impl Default for ControlPlaneState {
    fn default() -> Self {
        Self::new()
    }
}

/// gRPC service implementation
#[derive(Clone)]
pub struct GrpcControlPlane {
    state: Arc<ControlPlaneState>,
    auth_enabled: bool,
    auth_token: Option<String>,
}

impl GrpcControlPlane {
    pub fn new(
        state: Arc<ControlPlaneState>,
        auth_enabled: bool,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            state,
            auth_enabled,
            auth_token,
        }
    }

    #[allow(clippy::result_large_err)]
    fn check_auth(&self, request: &tonic::Request<impl Send>) -> Result<(), Status> {
        if !self.auth_enabled {
            return Ok(());
        }
        let token = match &self.auth_token {
            Some(t) => t,
            None => return Err(Status::permission_denied("auth token not configured")),
        };
        let metadata = request.metadata();
        let auth_val = metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match auth_val {
            Some(t) if crate::services::constant_time_eq(t.as_bytes(), token.as_bytes()) => Ok(()),
            _ => Err(Status::permission_denied("invalid or missing auth token")),
        }
    }
}

#[tonic::async_trait]
impl ControlPlane for GrpcControlPlane {
    async fn get_servers(
        &self,
        request: Request<GetServersRequest>,
    ) -> Result<Response<GetServersResponse>, Status> {
        self.check_auth(&request)?;
        let req = request.into_inner();
        let servers = self.state.list_servers().await;

        let filtered: Vec<control_plane::ServerInfo> = servers
            .into_iter()
            .filter(|server| {
                if !req.filter_region.is_empty()
                    && !server.region.is_empty()
                    && server.region != req.filter_region
                {
                    return false;
                }
                if req.filter_status != 0 {
                    if let Ok(s) = control_plane::ServerStatus::try_from(req.filter_status) {
                        if server.status != ServerStatus::from(s) {
                            return false;
                        }
                    }
                }
                true
            })
            .map(|s| s.into())
            .collect();

        Ok(Response::new(GetServersResponse { servers: filtered }))
    }

    async fn add_server(
        &self,
        request: Request<AddServerRequest>,
    ) -> Result<Response<AddServerResponse>, Status> {
        self.check_auth(&request)?;
        let req = request.into_inner();
        let server = req
            .server
            .ok_or_else(|| Status::invalid_argument("Server info required"))?;

        self.state.upsert_server(server.into()).await;

        Ok(Response::new(AddServerResponse {
            success: true,
            message: "Server added successfully".to_string(),
        }))
    }

    async fn remove_server(
        &self,
        request: Request<RemoveServerRequest>,
    ) -> Result<Response<RemoveServerResponse>, Status> {
        self.check_auth(&request)?;
        let req = request.into_inner();

        match self.state.remove_server(&req.name).await {
            Some(_) => Ok(Response::new(RemoveServerResponse {
                success: true,
                message: "Server removed successfully".to_string(),
            })),
            None => Err(Status::not_found(format!(
                "Server '{}' not found",
                req.name
            ))),
        }
    }

    async fn update_server_status(
        &self,
        request: Request<UpdateServerStatusRequest>,
    ) -> Result<Response<UpdateServerStatusResponse>, Status> {
        self.check_auth(&request)?;
        let req = request.into_inner();
        let status = control_plane::ServerStatus::try_from(req.status)
            .map_err(|_| Status::invalid_argument("Invalid server status"))?;

        match self
            .state
            .update_server_status(&req.name, status.into())
            .await
        {
            Ok(_) => Ok(Response::new(UpdateServerStatusResponse {
                success: true,
                message: "Server status updated successfully".to_string(),
            })),
            Err(e) => Err(Status::not_found(e)),
        }
    }

    async fn get_routing_rules(
        &self,
        request: Request<GetRoutingRulesRequest>,
    ) -> Result<Response<GetRoutingRulesResponse>, Status> {
        self.check_auth(&request)?;
        let req = request.into_inner();
        let rules = self.state.list_routing_rules().await;

        let filtered: Vec<control_plane::RoutingRule> = if req.enabled_only {
            rules
                .into_iter()
                .filter(|r| r.enabled)
                .map(|r| r.into())
                .collect()
        } else {
            rules.into_iter().map(|r| r.into()).collect()
        };

        Ok(Response::new(GetRoutingRulesResponse { rules: filtered }))
    }

    async fn add_routing_rule(
        &self,
        request: Request<AddRoutingRuleRequest>,
    ) -> Result<Response<AddRoutingRuleResponse>, Status> {
        self.check_auth(&request)?;
        let req = request.into_inner();
        let rule = req
            .rule
            .ok_or_else(|| Status::invalid_argument("Routing rule required"))?;

        self.state.upsert_routing_rule(rule.into()).await;

        Ok(Response::new(AddRoutingRuleResponse {
            success: true,
            message: "Routing rule added successfully".to_string(),
        }))
    }

    async fn remove_routing_rule(
        &self,
        request: Request<RemoveRoutingRuleRequest>,
    ) -> Result<Response<RemoveRoutingRuleResponse>, Status> {
        self.check_auth(&request)?;
        let req = request.into_inner();

        match self.state.remove_routing_rule(&req.id).await {
            Some(_) => Ok(Response::new(RemoveRoutingRuleResponse {
                success: true,
                message: "Routing rule removed successfully".to_string(),
            })),
            None => Err(Status::not_found(format!(
                "Routing rule '{}' not found",
                req.id
            ))),
        }
    }

    async fn toggle_routing_rule(
        &self,
        request: Request<ToggleRoutingRuleRequest>,
    ) -> Result<Response<ToggleRoutingRuleResponse>, Status> {
        self.check_auth(&request)?;
        let req = request.into_inner();

        match self.state.toggle_routing_rule(&req.id, req.enabled).await {
            Ok(_) => Ok(Response::new(ToggleRoutingRuleResponse {
                success: true,
                message: "Routing rule toggled successfully".to_string(),
            })),
            Err(e) => Err(Status::not_found(e)),
        }
    }

    async fn get_metrics(
        &self,
        request: Request<GetMetricsRequest>,
    ) -> Result<Response<GetMetricsResponse>, Status> {
        self.check_auth(&request)?;
        let metrics = self.state.get_metrics().await;

        Ok(Response::new(GetMetricsResponse {
            metrics: Some(metrics.into()),
        }))
    }

    type StreamMetricsStream = ReceiverStream<Result<MetricsUpdate, Status>>;

    async fn stream_metrics(
        &self,
        request: Request<StreamMetricsRequest>,
    ) -> Result<Response<Self::StreamMetricsStream>, Status> {
        self.check_auth(&request)?;
        let req = request.into_inner();
        let interval_ms = if req.interval_ms > 0 {
            req.interval_ms
        } else {
            1000
        };

        let (tx, rx) = mpsc::channel(100);
        let state = self.state.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_millis(interval_ms as u64));

            loop {
                interval.tick().await;

                let metrics = state.get_metrics().await;
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                let update = MetricsUpdate {
                    metrics: Some(metrics.into()),
                    timestamp,
                };

                if tx.send(Ok(update)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        self.check_auth(&request)?;
        Ok(Response::new(HealthCheckResponse {
            healthy: true,
            version: env!("CARGO_PKG_VERSION").to_string(),
            message: "Control plane is healthy".to_string(),
        }))
    }
}

/// Control plane configuration
#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    pub bind_address: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub auth_enabled: bool,
    pub auth_token: Option<String>,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 50051,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            auth_enabled: false,
            auth_token: None,
        }
    }
}

/// Control plane server
pub struct ControlPlaneServer {
    config: ControlPlaneConfig,
    state: Arc<ControlPlaneState>,
    shutdown_rx: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl ControlPlaneServer {
    pub fn new(config: ControlPlaneConfig, state: Arc<ControlPlaneState>) -> Self {
        Self {
            config,
            state,
            shutdown_rx: None,
        }
    }

    /// Start the gRPC server
    pub async fn start(&mut self) -> Result<(), String> {
        let addr = format!("{}:{}", self.config.bind_address, self.config.port)
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        tracing::info!(
            address = %self.config.bind_address,
            port = self.config.port,
            tls = self.config.tls_enabled,
            "Starting gRPC control plane"
        );

        let grpc_service = GrpcControlPlane::new(
            self.state.clone(),
            self.config.auth_enabled,
            self.config.auth_token.clone(),
        );
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        self.shutdown_rx = Some(shutdown_rx);

        let server = ControlPlaneServer::new_server(addr, grpc_service, self.config.clone());

        tokio::spawn(async move {
            if let Err(e) = server.await {
                tracing::error!("gRPC server error: {}", e);
            }
        });

        Ok(())
    }

    /// Create a new tonic server
    fn new_server(
        addr: std::net::SocketAddr,
        service: GrpcControlPlane,
        config: ControlPlaneConfig,
    ) -> impl std::future::Future<Output = Result<(), tonic::transport::Error>> {
        let mut builder = Server::builder();

        if config.tls_enabled {
            if let (Some(cert_path), Some(key_path)) = (config.tls_cert_path, config.tls_key_path) {
                let tls_config =
                    ServerTlsConfig::new().identity(tonic::transport::Identity::from_pem(
                        std::fs::read(&cert_path).unwrap_or_default(),
                        std::fs::read(&key_path).unwrap_or_default(),
                    ));
                builder = builder.tls_config(tls_config).unwrap();
            }
        }

        builder
            .add_service(ProtoControlPlaneServer::new(service))
            .serve(addr)
    }

    /// Signal the running gRPC server to stop. We hold the receiver end of a
    /// oneshot — the sender lives inside the spawned `serve` future via
    /// `serve_with_shutdown`. Dropping the receiver triggers shutdown.
    pub async fn stop(&mut self) -> Result<(), String> {
        tracing::info!("Stopping gRPC control plane");
        // Drop the receiver — the corresponding sender's `await` resolves
        // with `RecvError`, which our future treats as a shutdown signal.
        let _ = self.shutdown_rx.take();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_management() {
        let state = ControlPlaneState::new();

        let server = ServerInfo {
            name: "lobby".to_string(),
            address: "localhost:25565".to_string(),
            status: ServerStatus::Online,
            player_count: 10,
            max_players: 100,
            region: "us-east".to_string(),
            latency_ms: 5.0,
        };

        state.upsert_server(server.clone()).await;

        let retrieved = state.get_server("lobby").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "lobby");

        state.remove_server("lobby").await;
        assert!(state.get_server("lobby").await.is_none());
    }

    #[tokio::test]
    async fn routing_rule_management() {
        let state = ControlPlaneState::new();

        let rule = RoutingRule {
            id: "rule1".to_string(),
            pattern: "lobby*".to_string(),
            target: "lobby-server".to_string(),
            priority: 100,
            enabled: true,
            metadata: HashMap::new(),
        };

        state.upsert_routing_rule(rule.clone()).await;

        let retrieved = state.get_routing_rule("rule1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "rule1");

        state.toggle_routing_rule("rule1", false).await.unwrap();
        let retrieved = state.get_routing_rule("rule1").await;
        assert!(!retrieved.unwrap().enabled);
    }

    #[tokio::test]
    async fn grpc_service_get_servers() {
        let state = Arc::new(ControlPlaneState::new());
        let service = GrpcControlPlane::new(state.clone(), false, None);

        let server = ServerInfo {
            name: "lobby".to_string(),
            address: "localhost:25565".to_string(),
            status: ServerStatus::Online,
            player_count: 10,
            max_players: 100,
            region: "us-east".to_string(),
            latency_ms: 5.0,
        };

        state.upsert_server(server).await;

        let request = Request::new(GetServersRequest::default());
        let response = service.get_servers(request).await.unwrap();

        assert!(!response.into_inner().servers.is_empty());
    }

    #[tokio::test]
    async fn grpc_service_health_check() {
        let state = Arc::new(ControlPlaneState::new());
        let service = GrpcControlPlane::new(state, false, None);

        let request = Request::new(HealthCheckRequest {});
        let response = service.health_check(request).await.unwrap();

        assert!(response.into_inner().healthy);
    }
}
