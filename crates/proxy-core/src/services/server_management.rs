//! TCP-based backend orchestration channel.
//!
//! A small protocol for orchestrators (custom CI scripts, the
//! Kojacoord launcher) to register/deregister backends and transfer
//! players without going through the gRPC control plane. Bound to
//! `[server_management] bind`; constant-time-compared auth token
//! per message so accept-rate brute-force doesn't leak token bytes.

use crate::proxy::ProxyState;
use crate::server::BackendServer;
use crate::transfer::TransferCommand;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRegistration {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub template: Option<String>,
    #[serde(default = "default_max_players")]
    pub max_players: u32,
    pub auth_token: String,
}

fn default_max_players() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatusUpdate {
    pub name: String,
    pub online: bool,
    pub player_count: Option<usize>,
    pub auth_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerDeregistration {
    pub name: String,
    pub auth_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerTransfer {
    pub uuid: String,
    pub server: String,
    pub auth_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEvacuation {
    pub from_server: String,
    pub to_server: String,
    pub auth_token: String,
}

pub struct ServerManagementServer {
    state: Arc<ProxyState>,
    bind_address: String,
    auth_token: String,
}

impl ServerManagementServer {
    pub fn new(state: Arc<ProxyState>, bind_address: String, auth_token: String) -> Self {
        Self {
            state,
            bind_address,
            auth_token,
        }
    }

    pub async fn spawn(self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&self.bind_address)
            .await
            .with_context(|| format!("Failed to bind TCP server to {}", self.bind_address))?;

        info!(
            "Server management TCP server listening on {}",
            self.bind_address
        );

        tokio::spawn(async move {
            while let Ok((stream, addr)) = listener.accept().await {
                debug!("Accepted connection from {}", addr);
                let handler = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = handler.handle_connection(stream).await {
                        error!("Error handling connection: {}", e);
                    }
                });
            }
        });

        Ok(())
    }

    async fn handle_connection(&self, mut stream: TcpStream) -> anyhow::Result<()> {
        let peer_addr = stream.peer_addr().ok();
        debug!("Accepted server management connection from {:?}", peer_addr);

        let (reader, _writer) = stream.split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        buf_reader.read_line(&mut line).await?;
        if line.len() > 65536 {
            anyhow::bail!("line exceeds 64 KiB limit");
        }

        debug!("Received message: {}", line.trim());

        if let Ok(registration) = serde_json::from_str::<ServerRegistration>(&line) {
            self.handle_registration(registration, &mut stream).await?;
        } else if let Ok(status_update) = serde_json::from_str::<ServerStatusUpdate>(&line) {
            self.handle_status_update(status_update, &mut stream)
                .await?;
        } else if let Ok(deregistration) = serde_json::from_str::<ServerDeregistration>(&line) {
            self.handle_deregistration(deregistration, &mut stream)
                .await?;
        } else if let Ok(transfer) = serde_json::from_str::<PlayerTransfer>(&line) {
            self.handle_player_transfer(transfer, &mut stream).await?;
        } else if let Ok(evacuation) = serde_json::from_str::<ServerEvacuation>(&line) {
            self.handle_evacuation(evacuation, &mut stream).await?;
        } else {
            warn!("Failed to parse message as any known type");
            stream.write_all(b"ERROR: Invalid message format\n").await?;
        }

        Ok(())
    }

    async fn handle_registration(
        &self,
        registration: ServerRegistration,
        stream: &mut TcpStream,
    ) -> anyhow::Result<()> {
        debug!("Received server registration from {}", registration.name);

        if !crate::services::constant_time_eq(
            registration.auth_token.as_bytes(),
            self.auth_token.as_bytes(),
        ) {
            warn!("Invalid auth token from server {}", registration.name);
            stream.write_all(b"ERROR: Invalid auth token\n").await?;
            return Ok(());
        }

        info!(
            "Registering server: {} at {}:{} (template: {:?}, max_players: {})",
            registration.name,
            registration.address,
            registration.port,
            registration.template,
            registration.max_players
        );

        let addr: SocketAddr = format!("{}:{}", registration.address, registration.port)
            .parse()
            .context("Invalid server address")?;

        debug!("Parsed server address: {}", addr);

        if self.state.server_registry.get(&registration.name).is_some() {
            warn!("Server {} already registered, updating", registration.name);
            self.state.server_registry.remove(&registration.name);
        }

        let server = BackendServer {
            name: registration.name.clone(),
            address: addr,
            restricted: false,
            forwarding_override: None,
            player_count: Arc::new(AtomicUsize::new(0)),
            online: Arc::new(AtomicBool::new(true)),
            connection_pool: None,
            backend_type: kojacoord_config::BackendType::default(),
            compression_threshold: 0,
            cipher_suites: String::new(),
            health_probe_interval_secs: 0,
            health_probe_timeout_secs: 5,
            health_probe_fail_threshold: 3,
            health_fail_count: Arc::new(AtomicU32::new(0)),
            health_unhealthy: Arc::new(AtomicBool::new(false)),
            region: String::new(),
        };

        self.state.server_registry.register(server).await;
        info!("Server {} successfully registered", registration.name);
        stream.write_all(b"OK: Server registered\n").await?;

        Ok(())
    }

    async fn handle_status_update(
        &self,
        status_update: ServerStatusUpdate,
        stream: &mut TcpStream,
    ) -> anyhow::Result<()> {
        debug!("Received status update from server {}", status_update.name);

        if !crate::services::constant_time_eq(
            status_update.auth_token.as_bytes(),
            self.auth_token.as_bytes(),
        ) {
            warn!(
                "Invalid auth token for status update from server {}",
                status_update.name
            );
            stream.write_all(b"ERROR: Invalid auth token\n").await?;
            return Ok(());
        }

        if let Some(server) = self.state.server_registry.get(&status_update.name) {
            let was_online = server.online.load(std::sync::atomic::Ordering::Relaxed);
            server
                .online
                .store(status_update.online, std::sync::atomic::Ordering::Relaxed);
            if let Some(count) = status_update.player_count {
                server
                    .player_count
                    .store(count, std::sync::atomic::Ordering::Relaxed);
            }
            info!(
                "Updated status for server {}: online={} (was: {}), players={:?}",
                status_update.name, status_update.online, was_online, status_update.player_count
            );
            stream.write_all(b"OK: Status updated\n").await?;
        } else {
            warn!("Server {} not found for status update", status_update.name);
            stream.write_all(b"ERROR: Server not found\n").await?;
        }

        Ok(())
    }

    async fn handle_deregistration(
        &self,
        deregistration: ServerDeregistration,
        stream: &mut TcpStream,
    ) -> anyhow::Result<()> {
        debug!(
            "Received deregistration from server {}",
            deregistration.name
        );

        if !crate::services::constant_time_eq(
            deregistration.auth_token.as_bytes(),
            self.auth_token.as_bytes(),
        ) {
            warn!(
                "Invalid auth token for deregistration from server {}",
                deregistration.name
            );
            stream.write_all(b"ERROR: Invalid auth token\n").await?;
            return Ok(());
        }

        if self
            .state
            .server_registry
            .get(&deregistration.name)
            .is_some()
        {
            // Evacuate any remaining players to the default (lobby) server before removing.
            let default_server = self
                .state
                .config
                .servers
                .first()
                .map(|s| s.name.clone())
                .unwrap_or_else(|| "lobby".to_owned());
            self.evacuate_players(&deregistration.name, &default_server)
                .await;

            self.state.server_registry.remove(&deregistration.name);
            info!("Deregistered server {}", deregistration.name);
            stream.write_all(b"OK: Server deregistered\n").await?;
        } else {
            warn!(
                "Server {} not found for deregistration",
                deregistration.name
            );
            stream.write_all(b"ERROR: Server not found\n").await?;
        }

        Ok(())
    }

    async fn handle_evacuation(
        &self,
        evacuation: ServerEvacuation,
        stream: &mut TcpStream,
    ) -> anyhow::Result<()> {
        debug!(
            "Received evacuation request: {} -> {}",
            evacuation.from_server, evacuation.to_server
        );

        if !crate::services::constant_time_eq(
            evacuation.auth_token.as_bytes(),
            self.auth_token.as_bytes(),
        ) {
            warn!("Invalid auth token for server evacuation");
            stream.write_all(b"ERROR: Invalid auth token\n").await?;
            return Ok(());
        }

        let count = self
            .evacuate_players(&evacuation.from_server, &evacuation.to_server)
            .await;
        info!(
            "Evacuated {} players from {} to {}",
            count, evacuation.from_server, evacuation.to_server
        );
        stream
            .write_all(format!("OK: Evacuated {} players\n", count).as_bytes())
            .await?;

        Ok(())
    }

    /// Move all players currently on `from_server` to `to_server`.
    /// Returns the number of players evacuated.
    ///
    /// Snapshots the session map up front: the DashMap iterator holds
    /// per-shard guards, and `kick_player()` reaches back into the same
    /// map. Reentering a held shard would deadlock.
    async fn evacuate_players(&self, from_server: &str, to_server: &str) -> usize {
        let snapshot: Vec<(Uuid, crate::session::SharedSession)> = self
            .state
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

                if let Some(old) = self.state.server_registry.get(from_server) {
                    old.player_count.fetch_sub(1, Ordering::Relaxed);
                }
                if let Some(new_srv) = self.state.server_registry.get(to_server) {
                    new_srv.player_count.fetch_add(1, Ordering::Relaxed);
                }

                let reason = r#"{"text":"§cThe server you were on has shut down. Reconnecting you to the lobby..."}"#;
                self.state.kick_player(&uuid, reason).await;

                evacuated += 1;
            }
        }

        evacuated
    }

    async fn handle_player_transfer(
        &self,
        transfer: PlayerTransfer,
        stream: &mut TcpStream,
    ) -> anyhow::Result<()> {
        if !crate::services::constant_time_eq(
            transfer.auth_token.as_bytes(),
            self.auth_token.as_bytes(),
        ) {
            warn!("Invalid auth token for player transfer");
            stream.write_all(b"ERROR: Invalid auth token\n").await?;
            return Ok(());
        }

        let player_uuid =
            Uuid::parse_str(&transfer.uuid).map_err(|_| anyhow::anyhow!("Invalid UUID format"))?;

        info!(
            "Transferring player {} to server {} using kojacoord protocol",
            transfer.uuid, transfer.server
        );

        let _command = TransferCommand::ConnectOther {
            server: transfer.server.clone(),
            uuid: player_uuid,
        };

        if let Some(target) = self.state.sessions.get(&player_uuid) {
            if let Some(old_name) = target.read().await.current_server.clone() {
                if let Some(old) = self.state.server_registry.get(&old_name) {
                    old.player_count.fetch_sub(1, Ordering::Relaxed);
                    debug!("Decremented player count for old server {}", old_name);
                }
            }
            if let Some(new_srv) = self.state.server_registry.get(&transfer.server) {
                new_srv.player_count.fetch_add(1, Ordering::Relaxed);
                debug!(
                    "Incremented player count for new server {}",
                    transfer.server
                );
            }
            target.write().await.current_server = Some(transfer.server.clone());
            target.write().await.transferred = true;

            info!(
                "Successfully transferred player {} to server {}",
                transfer.uuid, transfer.server
            );

            stream.write_all(b"OK: Transfer completed\n").await?;
        } else {
            warn!("Player {} not found in active sessions", transfer.uuid);
            stream.write_all(b"ERROR: Player not found\n").await?;
        }

        Ok(())
    }
}

impl Clone for ServerManagementServer {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            bind_address: self.bind_address.clone(),
            auth_token: self.auth_token.clone(),
        }
    }
}
