//! Config schema for the proxy.
//!
//! Mirrors the on-disk `config.toml` 1:1. Every struct here is
//! `serde::Deserialize` so the loader can deserialize directly from
//! TOML and most use `#[serde(default)]` so operators only have to
//! write the fields they care about — defaults live in the per-section
//! `Default` impls below.
//!
//! Hot-reloadable fields are flagged in the field comments; anything
//! not marked needs a process restart to take effect.

#![deny(clippy::all)]

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxy: ProxySection,

    pub listeners: ListenersSection,

    pub forwarding: ForwardingSection,

    #[serde(default)]
    pub servers: Vec<ServerEntry>,

    #[serde(default)]
    pub routing: RoutingConfig,

    #[serde(default)]
    pub database: DatabaseConfig,

    #[serde(default)]
    pub server_management: ServerManagementConfig,

    #[serde(default)]
    pub http_api: HttpApiConfig,

    #[serde(default)]
    pub cluster: ClusterConfig,

    #[serde(default)]
    pub plugins: PluginConfig,

    /// Plugin permission grants: map of plugin name to list of allowed permissions
    #[serde(default)]
    pub plugin_permissions: std::collections::HashMap<String, Vec<String>>,

    /// Failover groups for active-passive backend redundancy
    #[serde(default)]
    pub failover_groups: Vec<FailoverGroup>,

    #[serde(default)]
    pub metrics: MetricsConfig,

    #[serde(default)]
    pub telemetry: TelemetryConfig,

    #[serde(default)]
    pub metrics_backend: MetricsBackendConfig,

    #[serde(default)]
    pub grpc_control_plane: GrpcControlPlaneConfig,
}

/// One `[[failover_groups]]` block. The runtime mirror lives in
/// `proxy_core::failover::FailoverGroupState` — keep the two in sync
/// when adding fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverGroup {
    /// Group identifier; referenced by routing rules via
    /// `target = "group:<name>"`.
    pub name: String,
    /// Server that receives traffic while healthy.
    pub primary: String,
    /// Ordered fallbacks. The monitor walks the list top-to-bottom
    /// when the active server fails; the first healthy entry wins.
    pub standbys: Vec<String>,
    /// If true, traffic moves back to `primary` automatically once it
    /// passes a probe. If false, the failover sticks until an operator
    /// resets it manually.
    #[serde(default = "default_failback")]
    pub auto_failback: bool,
}

fn default_failback() -> bool {
    true // Auto-failback enabled by default
}

fn default_resource_pack_required() -> bool {
    false // Optional by default
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySection {
    #[serde(default = "default_bind")]
    pub bind: String,

    #[serde(default = "default_online_mode")]
    pub online_mode: bool,

    #[serde(default = "default_ip_forward")]
    pub ip_forward: bool,

    #[serde(default = "default_compression_threshold")]
    pub compression_threshold: i32,

    #[serde(default = "default_max_players")]
    pub max_players: usize,

    #[serde(default)]
    pub prevent_proxy_connections: bool,

    /// Enable HAProxy PROXY protocol v1/v2 support so the real client IP is
    /// forwarded from an upstream load balancer (e.g. HAProxy, nginx, Traefik).
    #[serde(default = "default_proxy_protocol")]
    pub proxy_protocol: bool,

    /// When enabled, PROXY protocol headers are optional - if no header is detected,
    /// the connection proceeds with the direct address. This allows the proxy to work
    /// both behind a load balancer and with direct connections.
    #[serde(default)]
    pub proxy_protocol_optional: bool,

    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,

    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,

    /// Resource pack URL to force on all clients
    #[serde(default)]
    pub resource_pack_url: Option<String>,

    /// Resource pack hash for verification (SHA-1)
    #[serde(default)]
    pub resource_pack_hash: Option<String>,

    /// Whether to require the resource pack (force download)
    #[serde(default = "default_resource_pack_required")]
    pub resource_pack_required: bool,

    /// Resource pack prompt message shown to clients
    #[serde(default)]
    pub resource_pack_prompt: Option<String>,

    /// Enable cookies & transfers passthrough (1.20.5+)
    /// Preserves server-driven reconnects by relaying cookie and transfer packets
    #[serde(default)]
    pub cookies_transfers_passthrough: bool,

    /// Enable chat signing translation (1.19+)
    /// Signs/strips chat messages when bridging between versions
    #[serde(default)]
    pub chat_signing_translation: bool,

    /// New connections allowed per source IP within a short window before a
    /// temporary ban. `0` disables connection throttling. Defaults to a value
    /// tolerant of shared/CGNAT addresses.
    #[serde(default = "default_max_conns_per_ip")]
    pub max_connections_per_ip: u32,

    #[serde(default = "default_lobby_name")]
    pub lobby_server_name: String,

    #[serde(default)]
    pub lobby_server_protocol: u32,

    /// Stable node identity — generated once on first run and persisted to the
    /// config file. Never regenerated unless the field is manually cleared.
    #[serde(default)]
    pub server_id: String,

    #[serde(default)]
    pub eula_accepted: bool,

    #[serde(default = "default_auth_url")]
    pub auth_url: String,

    #[serde(default = "default_public_key")]
    pub mojang_public_key: String,
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            online_mode: default_online_mode(),
            compression_threshold: default_compression_threshold(),
            ip_forward: default_ip_forward(),
            max_players: default_max_players(),
            prevent_proxy_connections: false,
            proxy_protocol: default_proxy_protocol(),
            proxy_protocol_optional: false,
            trusted_proxies: Vec::new(),
            session_timeout_secs: default_session_timeout(),
            resource_pack_url: None,
            resource_pack_hash: None,
            resource_pack_required: false,
            resource_pack_prompt: None,
            cookies_transfers_passthrough: false,
            chat_signing_translation: false,
            max_connections_per_ip: default_max_conns_per_ip(),
            lobby_server_name: default_lobby_name(),
            lobby_server_protocol: 47,
            // Empty on first construction — ensure_server_id() fills and
            // persists the value before Figment reads the file.
            server_id: String::new(),
            eula_accepted: false,
            auth_url: default_auth_url(),
            mojang_public_key: default_public_key(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenersSection {
    #[serde(default = "default_motd")]
    pub motd: String,

    #[serde(default)]
    pub motd_json: Option<serde_json::Value>,

    #[serde(default)]
    pub server_lore: Option<String>,

    #[serde(default)]
    pub tab_list: TabListMode,
}

impl Default for ListenersSection {
    fn default() -> Self {
        Self {
            motd: default_motd(),
            motd_json: None,
            server_lore: None,
            tab_list: TabListMode::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TabListMode {
    #[default]
    GlobalPing,
    ServerPing,
    Hidden,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardingSection {
    #[serde(default)]
    pub mode: ForwardingMode,

    #[serde(default)]
    pub velocity_secret: String,
}

impl Default for ForwardingSection {
    fn default() -> Self {
        Self {
            mode: ForwardingMode::None,
            velocity_secret: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ForwardingMode {
    #[default]
    None,
    Bungeecord,
    Velocity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    #[default]
    Spigot,
    Forge,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub name: String,

    pub address: String,

    #[serde(default)]
    pub restricted: bool,

    #[serde(default)]
    pub forwarding_override: Option<ForwardingMode>,

    #[serde(default)]
    pub max_players: Option<usize>,

    #[serde(default)]
    pub display_name: Option<String>,

    #[serde(default)]
    pub motd: Option<String>,

    #[serde(default)]
    pub modpack: Option<String>,

    #[serde(default)]
    pub modpack_version: Option<String>,

    #[serde(default)]
    pub game_type: Option<String>,

    /// Per-server compression threshold. Overrides the global proxy setting.
    /// -1 to disable compression for this server, 0 to use global default.
    #[serde(default = "default_server_compression")]
    pub compression_threshold: i32,

    /// Cipher suite pinning for this server's TLS connection (if using TLS).
    /// Empty string uses default cipher suites.
    #[serde(default)]
    pub cipher_suites: String,

    /// Health probe interval in seconds. 0 disables health probes for this server.
    #[serde(default)]
    pub health_probe_interval_secs: u64,

    /// Health probe timeout in seconds.
    #[serde(default = "default_health_probe_timeout")]
    pub health_probe_timeout_secs: u64,

    /// Number of consecutive probe failures before marking server as unhealthy.
    #[serde(default = "default_health_probe_threshold")]
    pub health_probe_fail_threshold: u32,

    /// Region for this server (e.g., "us-east", "eu-west", "asia")
    #[serde(default)]
    pub region: String,

    #[serde(default)]
    pub backend_protocol: u32,

    #[serde(default)]
    pub backend_type: BackendType,
}

/// Top-level routing config (see `[routing]` / `[[routing.rules]]` in the
/// configuration file). Evaluated by `proxy_core::routing::RoutingRules`
/// after the player's name and IP are known. See ROADMAP.md item
/// "Per-player and per-region routing rules".
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingConfig {
    #[serde(default)]
    pub rules: Vec<RouteRuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteRuleConfig {
    /// Human-readable label, shows up in logs.
    #[serde(default)]
    pub label: String,
    /// Case-insensitive glob (`*` wildcards) for the player username. Omit
    /// for "any name".
    #[serde(default)]
    pub name_glob: Option<String>,
    /// IPv4/IPv6 CIDR strings (`"10.0.0.0/8"`, `"2001:db8::/32"`). Empty list
    /// = "any IP".
    #[serde(default)]
    pub client_cidrs: Vec<String>,
    /// Target server name (must match a `[[servers]].name`).
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DatabaseConfig {
    #[serde(default)]
    pub url: String,

    #[serde(default = "default_db_pool_size")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClusterConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub node_address: String,

    #[serde(default)]
    pub seed_nodes: Vec<String>,

    #[serde(default = "default_max_players")]
    pub max_players: usize,

    #[serde(default)]
    pub load_balancing_strategy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub plugin_dir: String,

    #[serde(default)]
    pub configs: std::collections::HashMap<String, std::collections::HashMap<String, String>>,

    /// Watch `plugin_dir` for changes and hot-reload plugins whose DLL/SO/
    /// DYLIB mtime advances. Implemented via polling (no `notify` dep).
    #[serde(default)]
    pub hot_reload: bool,

    /// Poll interval in seconds for the hot-reload watcher. Defaults to 5.
    #[serde(default = "default_hot_reload_interval")]
    pub hot_reload_interval_secs: u64,
}

fn default_hot_reload_interval() -> u64 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_metrics_bind")]
    pub bind: String,

    #[serde(default)]
    pub retention_hours: u64,
}

/// Anonymous, opt-out usage telemetry. When enabled, the proxy periodically
/// posts coarse, non-identifying metrics to the Kojacoord metrics endpoint
/// (metric.kojacoord.net). Set `enabled = false` to disable it completely — the
/// proxy then never contacts the endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default = "bool_true")]
    pub enabled: bool,

    #[serde(default = "default_telemetry_endpoint")]
    pub endpoint: String,

    #[serde(default = "default_telemetry_interval")]
    pub interval_secs: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: default_telemetry_endpoint(),
            interval_secs: default_telemetry_interval(),
        }
    }
}

fn default_telemetry_endpoint() -> String {
    "https://metrics.kojacraft.net".into()
}

fn default_telemetry_interval() -> u64 {
    // Every 30 minutes is plenty for adoption metrics and is gentle on the endpoint.
    1800
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpApiConfig {
    #[serde(default = "bool_true")]
    pub enabled: bool,

    #[serde(default = "default_http_bind")]
    pub bind: String,

    #[serde(default = "default_http_token")]
    pub auth_token: String,
}

impl Default for HttpApiConfig {
    fn default() -> Self {
        Self {
            enabled: bool_true(),
            bind: default_http_bind(),
            auth_token: default_http_token(),
        }
    }
}

fn default_http_bind() -> String {
    "127.0.0.1:8081".into()
}

fn default_http_token() -> String {
    // Intentionally empty: a real secret must be configured (or is auto-generated
    // on first run). Validation rejects empty/placeholder tokens at startup.
    String::new()
}

fn default_public_key() -> String {
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAylB4B6m5lz7jwrcFz6Fd/fnfUhcvlxsTSn5kIK/2aGG1C3kMy4VjhwlxF6BFUSnfxhNswPjh3ZitkBxEAFY25uzkJFRwHwVA9mdwjashXILtR6OqdLXXFVyUPIURLOSWqGNBtb08EN5fMnG8iFLgEJIBMxs9BvF3s3/FhuHyPKiVTZmXY0WY4ZyYqvoKR+XjaTRPPvBsDa4WI2u1zxXMeHlodT3lnCzVvyOYBLXL6CJgByuOxccJ8hnXfF9yY4F0aeL080Jz/3+EBNG8RO4ByhtBf4Ny8NQ6stWsjfeUIvH7bU/4zCYcYOq4WrInXHqS8qruDmIl7P5XXGcabuzQstPf/h2CRAUpP/PlHXcMlvewjmGU6MfDK+lifScNYwjPxRo4nKTGFZf/0aqHCh/EAsQyLKrOIYRE0lDG3bzBh8ogIMLAugsAfBb6M3mqCqKaTMAf/VAjh5FFJnjS+7bE+bZEV0qwax1CEoPPJL1fIQjOS8zj086gjpGRCtSy9+bTPTfTR/SJ+VUB5G2IeCItnkNHpJX2ygojFZ9n5Fnj7R9ZnOM+L8nyIjPu3aePvtcrXlyLhH/hvOfIOjPxOlqW+O5QwSFP4OEcyLAUgDdUgyW36Z5mB285uKW/ighzZsOTevVUG2QwDItObIV6i8RCxFbN2oDHyPaO5j1tTaBNyVt8CAwEAAQ==".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerManagementConfig {
    #[serde(default = "default_management_enabled")]
    pub enabled: bool,

    #[serde(default = "default_management_bind")]
    pub bind: String,

    #[serde(default = "default_management_auth_token")]
    pub auth_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsBackendConfig {
    #[serde(default)]
    pub url: String,

    #[serde(default)]
    pub token: String,
}

/// gRPC control plane configuration for external orchestration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcControlPlaneConfig {
    #[serde(default = "default_grpc_enabled")]
    pub enabled: bool,

    #[serde(default = "default_grpc_bind_address")]
    pub bind_address: String,

    #[serde(default = "default_grpc_port")]
    pub port: u16,

    #[serde(default)]
    pub tls_enabled: bool,

    #[serde(default)]
    pub tls_cert_path: Option<String>,

    #[serde(default)]
    pub tls_key_path: Option<String>,

    #[serde(default)]
    pub auth_enabled: bool,

    #[serde(default)]
    pub auth_token: Option<String>,
}

impl Default for GrpcControlPlaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_grpc_bind_address(),
            port: default_grpc_port(),
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            auth_enabled: false,
            auth_token: None,
        }
    }
}

fn default_grpc_enabled() -> bool {
    false
}

fn default_grpc_bind_address() -> String {
    "127.0.0.1".to_string()
}

fn default_grpc_port() -> u16 {
    50051
}

// ── Default value functions ────────────────────────────────────────────────────

fn default_bind() -> String {
    "0.0.0.0:25565".into()
}
fn default_online_mode() -> bool {
    true
}
/// HAProxy PROXY protocol is off by default — most home/small setups don't need it.
fn default_proxy_protocol() -> bool {
    false
}
fn default_ip_forward() -> bool {
    false
}
fn default_compression_threshold() -> i32 {
    256
}
fn default_max_players() -> usize {
    1000
}
fn default_motd() -> String {
    "KojacoordNetwork".into()
}
fn default_session_timeout() -> u64 {
    5
}
fn default_max_conns_per_ip() -> u32 {
    8
}
fn default_db_pool_size() -> u32 {
    10
}
fn bool_true() -> bool {
    true
}
fn default_lobby_name() -> String {
    "lobby".into()
}
fn default_management_enabled() -> bool {
    // Opt-in: the management TCP control plane is an advanced clustering feature
    // and should not be exposed unless explicitly enabled with a strong token.
    false
}
fn default_management_bind() -> String {
    "127.0.0.1:25566".into()
}
fn default_management_auth_token() -> String {
    // Intentionally empty: see default_http_token().
    String::new()
}
fn default_auth_url() -> String {
    "https://sessionserver.mojang.com/session/minecraft/hasJoined".into()
}
fn default_metrics_bind() -> String {
    "127.0.0.1:9090".into()
}

fn default_server_compression() -> i32 {
    0 // 0 means use global default
}

fn default_health_probe_timeout() -> u64 {
    5 // 5 seconds
}

fn default_health_probe_threshold() -> u32 {
    3 // 3 consecutive failures
}

// ── Secret utilities ───────────────────────────────────────────────────────────

/// Generate a cryptographically-strong random secret suitable for auth tokens.
pub fn generate_secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Generate a stable node identity UUID.
fn generate_server_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Minimum acceptable length (in bytes) for any operational secret/token.
pub const MIN_SECRET_LEN: usize = 16;

/// Well-known placeholder secrets that must never be used in production.
pub const FORBIDDEN_SECRETS: &[&str] = &[
    "changeme",
    "change-me",
    "change_me",
    "change_this_token_in_production",
    "secret",
    "default",
    "placeholder",
    "password",
    "token",
    "your-secret-token",
    "your-api-token",
];

fn is_forbidden_secret(value: &str) -> bool {
    let lowered = value.trim().to_ascii_lowercase();
    FORBIDDEN_SECRETS
        .iter()
        .any(|bad| lowered == *bad || lowered.contains(bad))
}

/// Validate a named secret: must be present, long enough, and not a placeholder.
fn validate_secret(name: &str, value: &str) -> Result<(), anyhow::Error> {
    let v = value.trim();
    if v.is_empty() {
        anyhow::bail!(
            "{name} is empty; set a unique, randomly generated value \
             (e.g. `openssl rand -hex 32`)."
        );
    }
    if v.len() < MIN_SECRET_LEN {
        anyhow::bail!(
            "{name} is too short ({} bytes); it must be at least {} bytes.",
            v.len(),
            MIN_SECRET_LEN
        );
    }
    if is_forbidden_secret(v) {
        anyhow::bail!(
            "{name} matches a well-known placeholder value; \
             set a unique, randomly generated secret."
        );
    }
    Ok(())
}

// ── ProxyConfig impl ───────────────────────────────────────────────────────────

impl ProxyConfig {
    /// Ensures a stable `proxy.server_id` exists in the TOML file on disk.
    ///
    /// - If the field is already present and non-empty the existing value is
    ///   returned unchanged.
    /// - If the field is absent or empty a new UUID v4 is generated, written
    ///   back to the file, and returned.
    ///
    /// Must be called before [`from_file`] so that Figment picks up the
    /// persisted value on the same load.
    pub fn ensure_server_id(path: impl AsRef<Path>) -> Result<String, anyhow::Error> {
        use std::fs;

        let raw = fs::read_to_string(path.as_ref()).unwrap_or_default();
        let mut doc: toml_edit::DocumentMut = raw.parse()?;

        // Check whether proxy.server_id is already a non-empty string.
        if let Some(proxy) = doc.get("proxy") {
            if let Some(id) = proxy.get("server_id") {
                if let Some(s) = id.as_str() {
                    if !s.trim().is_empty() {
                        return Ok(s.to_string());
                    }
                }
            }
        }

        // Generate, write back, and return the new ID.
        let new_id = generate_server_id();

        // Ensure the [proxy] table exists before writing into it.
        if doc.get("proxy").is_none() {
            doc["proxy"] = toml_edit::table();
        }
        doc["proxy"]["server_id"] = toml_edit::value(new_id.clone());

        fs::write(path.as_ref(), doc.to_string())?;
        tracing::info!("Generated and persisted new server_id = {}", new_id);

        Ok(new_id)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        use figment::{
            providers::{Env, Format, Toml},
            Figment,
        };

        // Persist server_id first so Figment reads the stable value from disk.
        Self::ensure_server_id(path.as_ref())?;

        // Environment overrides use `__` to denote nesting so secrets can be
        // injected without baking them into the TOML, e.g.
        //   KOJA_HTTP_API__AUTH_TOKEN, KOJA_SERVER_MANAGEMENT__AUTH_TOKEN,
        //   KOJA_DATABASE__URL, KOJA_FORWARDING__VELOCITY_SECRET
        let config: ProxyConfig = Figment::new()
            .merge(Toml::file(path.as_ref()))
            .merge(Env::prefixed("KOJA_").split("__").global())
            .extract()?;

        config.validate()?;
        Ok(config)
    }

    /// Replace any empty/placeholder secret for an *enabled* control plane with a
    /// freshly generated strong token. Returns `true` if anything changed (so the
    /// caller can persist the updated config). Used on first run to make the proxy
    /// secure-by-default without operator action.
    pub fn ensure_secrets(&mut self) -> bool {
        let mut changed = false;
        if self.server_management.enabled
            && (self.server_management.auth_token.trim().is_empty()
                || is_forbidden_secret(&self.server_management.auth_token))
        {
            self.server_management.auth_token = generate_secret();
            changed = true;
        }
        if self.http_api.enabled
            && (self.http_api.auth_token.trim().is_empty()
                || is_forbidden_secret(&self.http_api.auth_token))
        {
            self.http_api.auth_token = generate_secret();
            changed = true;
        }
        changed
    }

    /// Fail fast on insecure security-sensitive configuration so the proxy never
    /// starts with publicly-known credentials or a forgeable forwarding secret.
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        // server_id must be present and non-empty after ensure_server_id().
        if self.proxy.server_id.trim().is_empty() {
            anyhow::bail!(
                "proxy.server_id is empty; this should have been populated by \
                 ensure_server_id() — check file write permissions."
            );
        }

        // Server-management control plane: only enforce when the feature is on.
        if self.server_management.enabled {
            validate_secret(
                "server_management.auth_token",
                &self.server_management.auth_token,
            )?;
        }

        // HTTP API control plane.
        if self.http_api.enabled {
            validate_secret("http_api.auth_token", &self.http_api.auth_token)?;
        }

        // Velocity modern forwarding relies entirely on the shared HMAC secret;
        // a weak/placeholder secret makes forwarded identity forgeable.
        if matches!(self.forwarding.mode, ForwardingMode::Velocity) {
            validate_secret(
                "forwarding.velocity_secret",
                &self.forwarding.velocity_secret,
            )?;
        }

        // Legacy BungeeCord forwarding is unauthenticated by design: warn loudly
        // so operators firewall their backends.
        if matches!(self.forwarding.mode, ForwardingMode::Bungeecord) {
            tracing::warn!(
                "forwarding.mode = bungeecord uses UNSIGNED legacy forwarding. Backends MUST \
                 only accept connections from this proxy (firewall them), otherwise players can \
                 spoof identities. Prefer Velocity modern forwarding with a strong secret."
            );
        }

        if self.grpc_control_plane.enabled && self.grpc_control_plane.auth_enabled {
            match &self.grpc_control_plane.auth_token {
                Some(token) => validate_secret("grpc_control_plane.auth_token", token)?,
                None => anyhow::bail!(
                    "grpc_control_plane.auth_token is not set; \
                     set a unique, randomly generated value when auth is enabled."
                ),
            }
        }

        Ok(())
    }
}

pub const DEFAULT_CONFIG: &str = include_str!("../default_config.toml");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_defaults() {
        let cfg: ProxyConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        assert_eq!(cfg.proxy.bind, "0.0.0.0:25565");
        assert!(cfg.proxy.online_mode);
        assert_eq!(cfg.proxy.compression_threshold, 256);
    }

    #[test]
    fn ensure_server_id_is_stable() {
        use std::fs;
        use tempfile::NamedTempFile;

        let file = NamedTempFile::new().unwrap();
        let path = file.path();

        // Write a minimal config with no server_id
        fs::write(path, "[proxy]\nbind = \"0.0.0.0:25565\"\n").unwrap();

        let id1 = ProxyConfig::ensure_server_id(path).unwrap();
        let id2 = ProxyConfig::ensure_server_id(path).unwrap();

        // Must be a valid UUID and stable across calls
        assert!(!id1.is_empty());
        assert_eq!(id1, id2, "server_id must not change between calls");

        // Must be present in the written file
        let raw = fs::read_to_string(path).unwrap();
        assert!(raw.contains(&id1), "server_id must be persisted to disk");
    }
}
