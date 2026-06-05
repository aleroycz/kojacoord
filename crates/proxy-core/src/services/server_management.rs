use crate::proxy::ProxyState;
use crate::server::BackendServer;
use crate::transfer::TransferCommand;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    pub max_players: u32,
    pub auth_token: String,
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
