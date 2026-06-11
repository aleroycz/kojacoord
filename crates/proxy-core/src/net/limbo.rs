//! Limbo: the fake play world we drop clients into when no backend
//! is available.
//!
//! When the routing rules can't find a healthy backend, or one
//! disconnects mid-session, we'd rather keep the client in the
//! protocol (looking at a flat-world spawn screen with a chat
//! message explaining the situation) than kick them. [`LimboHandler`]
//! synthesises the per-version JoinGame, position, abilities, and a
//! periodic keepalive — enough to keep the client connected and
//! polling for the backend to come back.
//!
//! Per-version packet construction lives in
//! [`crate::limbo_packets`] (one [`LimboPackets`] impl per canonical
//! bucket). The handler picks the right impl once at construction time
//! and every `send_*` method becomes a one-liner: build the
//! [`EncodedPacket`], frame it, write it.

use kojacoord_protocol::{ProtocolVersion, VersionRegistry};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{interval, Duration};
use uuid::Uuid;

use crate::{
    connection::McStream,
    error::ConnectionError,
    limbo_packets::{self, EncodedPacket, LimboPackets, PlayerPos, SoundParams},
    modloader,
    proxy::ProxyState,
    session::SharedSession,
};

const POLL_INTERVAL: Duration = Duration::from_secs(3);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const BOSSBAR_UUID: &str = "12345678-1234-1234-1234-123456789abc";

const LIMBO_X: f64 = 0.0;
const LIMBO_Y: f64 = 256.0;
const LIMBO_Z: f64 = 0.0;

/// World name for the synthetic limbo dimension. Deliberately distinct
/// from `minecraft:overworld` so that modern clients (1.16+) flush their
/// chunk cache when they transition into limbo and again when they
/// transition out into a real backend's overworld — otherwise the chunk
/// cache key collides with the backend's overworld and the player
/// appears frozen on stale chunks after a server switch.
const LIMBO_WORLD_NAME: &str = "kojacoord:limbo";

pub struct LimboHandler<'a> {
    stream: &'a mut McStream,
    state: Arc<ProxyState>,
    session: SharedSession,
    protocol_version: u32,
    compression_threshold: i32,
    ml_kind: modloader::ModloaderKind,

    target_server: Option<String>,

    /// Cached per-canonical-version packet builder. Selected once at
    /// construction time from `protocol_version`'s canonical bucket.
    packets: &'static dyn LimboPackets,
}

impl<'a> LimboHandler<'a> {
    pub fn new(
        stream: &'a mut McStream,
        state: Arc<ProxyState>,
        session: SharedSession,
        protocol_version: u32,
        compression_threshold: i32,
        ml_kind: modloader::ModloaderKind,
    ) -> Self {
        let canonical = VersionRegistry::nearest(protocol_version).canonical_typed_packet_version();
        let packets = limbo_packets::for_version(canonical);
        Self {
            stream,
            state,
            session,
            protocol_version,
            compression_threshold,
            ml_kind,
            target_server: None,
            packets,
        }
    }

    /// Send a pre-encoded packet (`(id, body)` pair). Dispatches to the
    /// framing helper that knows about pre-netty: 1.6.x writes
    /// `[id_u8][body]` raw with no length prefix and no compression
    /// layer, while 1.7+ varint-encodes the id, prepends it, then
    /// varint-length-frames the result with optional zlib compression.
    /// Without this branch every limbo packet sent to a 1.6.4 client
    /// went out as a modern frame on a pre-netty stream — the client
    /// reads the leading length varint as a garbage packet id and
    /// disconnects immediately.
    async fn send_encoded(&mut self, pkt: EncodedPacket) -> Result<(), ConnectionError> {
        crate::packet_io::write_typed_packet(
            &mut *self.stream,
            pkt.id,
            &pkt.body,
            self.protocol_version,
            self.compression_threshold,
        )
        .await
    }

    /// Build via the cached impl, then send. Skips if the impl returned
    /// `None` (this version doesn't speak that packet).
    async fn send_built(&mut self, built: Option<EncodedPacket>) -> Result<(), ConnectionError> {
        if let Some(pkt) = built {
            self.send_encoded(pkt).await
        } else {
            Ok(())
        }
    }

    /// Pin limbo to a specific backend (used by live server switching).
    /// Without this, limbo connects to whatever the routing rules currently pick.
    pub fn set_target(&mut self, server: String) {
        self.target_server = Some(server);
    }

    /// Top-level entry. Wraps [`Self::run_inner`] so any unrecoverable
    /// error sends a play-state Disconnect packet to the client before
    /// the limbo handler returns — without this, the TCP socket would
    /// just close and the client would see "Connection reset".
    ///
    /// Errors that mean "the client already left" (`Closed` or any
    /// `Io` error) are returned as-is without trying to write to the
    /// already-dead socket.
    pub async fn run(&mut self) -> Result<TcpStream, ConnectionError> {
        let result = self.run_inner().await;
        if let Err(ref e) = result {
            if !matches!(e, ConnectionError::Closed | ConnectionError::Io(_)) {
                let reason = serde_json::json!({
                    "text": format!("Limbo error: {}", e),
                    "color": "red",
                })
                .to_string();
                // Best-effort: ignore errors from the kick itself.
                let raw =
                    crate::packet_builder::build_disconnect_packet(&reason, self.protocol_version);
                let _ = crate::packet_io::write_packet(
                    &mut *self.stream,
                    &raw,
                    self.compression_threshold,
                )
                .await;
            }
        }
        result
    }

    async fn run_inner(&mut self) -> Result<TcpStream, ConnectionError> {
        let username = self.session.read().await.username.clone();
        tracing::info!(
            player = %username,
            protocol = self.protocol_version,
            version = ?self.ver(),
            ml_kind = ?self.ml_kind,
            "Entering limbo mode"
        );

        let teleport_id = 1_i32;

        // Configuration phase — proto 764+ (1.20.2+) sits between
        // LoginSuccess (already sent by `handle_login`) and the play
        // state we're about to enter with JoinGame. Skipping it leaves
        // 1.20.2+ clients stuck in the dirt-screen waiting on a
        // FinishConfiguration that never comes.
        //
        // The dance per minecraft.wiki
        // Java_Edition_protocol/Packets#Configuration:
        //   1. proxy reads ServerboundLoginAcknowledged (Login state, client)
        //   2. proxy sends ClientboundFinishConfiguration  (Configuration state)
        //   3. proxy reads ServerboundAcknowledgeFinishConfiguration (client)
        //   4. play state begins → send JoinGame
        //
        // We skip RegistryData entirely: vanilla 1.20.2 - 1.20.4 cope
        // because the client holds default registry data; 1.20.5+
        // (proto 766+) really wants registries but limbo is a brief
        // transit, and the missing dimension/biome entries surface as
        // generic placeholder textures rather than a disconnect.
        if self.protocol_version >= 764 {
            tracing::debug!(player = %username, proto = self.protocol_version, "Entering configuration phase");
            self.run_configuration_phase().await?;
        }

        tracing::debug!(player = %username, "Sending JoinGame/Login packet");
        self.send_login_play().await?;

        // Pre-netty essentials. Modern clients (1.7+) self-seed all
        // of these from JoinGame's coordinate / health / time fields,
        // so the `LimboPackets` default implementations return `None`
        // for them and `send_built(None)` no-ops. Only V1_6 actually
        // emits anything here — see `limbo_packets::v1_6::V1_6`.
        if self.protocol_version < 47 {
            let spawn = self.packets.spawn_position(
                self.protocol_version,
                PlayerPos {
                    x: LIMBO_X,
                    y: LIMBO_Y,
                    z: LIMBO_Z,
                    yaw: 0.0,
                    pitch: 0.0,
                },
            );
            self.send_built(spawn).await?;
            let time = self.packets.time_update(self.protocol_version);
            self.send_built(time).await?;
            let health = self.packets.update_health(self.protocol_version);
            self.send_built(health).await?;
        }

        if self.protocol_version >= 47 {
            tracing::debug!(player = %username, ml_kind = ?self.ml_kind, "Sending modloader brand");
            self.send_plugin_brand().await?;
        }

        // FML1 clients (1.6 Forge through 1.12 Forge) get stuck if the
        // server side never starts the `FML|HS` handshake. While limbo
        // can't speak FML, sending a HandshakeReset on the same channel
        // tells the client to drop into vanilla mode and stop waiting.
        if matches!(self.ml_kind, modloader::ModloaderKind::Fml1) {
            self.send_fml1_handshake_reset().await?;
        }

        tracing::debug!(player = %username, "Sending PlayerAbilities packet");
        self.send_player_abilities().await?;

        tracing::debug!(player = %username, "Sending HeldItemChange packet");
        self.send_held_item_change().await?;

        tracing::debug!(player = %username, "Sending PlayerPosition packet");
        self.send_player_position(teleport_id).await?;

        tracing::debug!(player = %username, "Sending limbo chat message");
        self.send_limbo_chat().await?;

        tracing::debug!(player = %username, "Sending note block sound");
        self.send_note_sound().await?;

        let has_bossbar = self.protocol_version >= 107;
        if has_bossbar {
            tracing::debug!(player = %username, "Sending BossBar add packet");
            self.send_bossbar_add().await?;
        }

        let mut poll = interval(POLL_INTERVAL);
        let mut keepalive = interval(KEEPALIVE_INTERVAL);
        let mut ka_id: i64 = 0;
        let mut poll_count = 0u64;

        tracing::info!(
            player = %username,
            poll_interval_sec = POLL_INTERVAL.as_secs(),
            keepalive_interval_sec = KEEPALIVE_INTERVAL.as_secs(),
            "Limbo loop started"
        );

        loop {
            tokio::select! {
                _ = poll.tick() => {
                    poll_count += 1;
                    tracing::trace!(player = %username, poll_count, "Polling for backend");
                    if let Some(backend) = self.try_connect_backend().await {
                        tracing::info!(
                            player = %username,
                            poll_attempts = poll_count,
                            "Backend online - leaving limbo"
                        );
                        if has_bossbar {
                            tracing::debug!(player = %username, "Sending BossBar remove packet");
                            self.send_bossbar_remove().await?;
                        }
                        tracing::debug!(player = %username, "Sending Respawn to transition out of limbo");
                        self.send_respawn().await?;
                        return Ok(backend);
                    }
                }
                _ = keepalive.tick() => {
                    ka_id = ka_id.wrapping_add(1);
                    tracing::trace!(player = %username, keepalive_id = ka_id, "Sending keepalive");
                    self.send_keepalive(ka_id).await?;
                }
                result = self.read_and_discard() => {
                    match result {
                        Ok(_) => tracing::trace!(player = %username, "Discarded client packet in limbo"),
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    /// Returns the [`ProtocolVersion`] whose typed-packet module limbo should
    /// use for this connection. Routed through `canonical_typed_packet_version`
    /// so every subversion (1.9, 1.10, 1.13, 1.14, …) falls onto one of the
    /// concrete variants the match arms below already handle. Without this,
    /// any modern subversion would silently fall through `_ => Ok(())` and the
    /// client would land in limbo without a JoinGame and time out.
    fn ver(&self) -> ProtocolVersion {
        VersionRegistry::nearest(self.protocol_version)
            .canonical_typed_packet_version()
            .as_protocol_version()
    }

    /// Drive the proto-764+ Login → Configuration → Play handshake.
    ///
    /// See the comment block above the call site for the wire-level
    /// step list. Errors out (so the outer `run_inner` can surface a
    /// disconnect) if any of the expected packet IDs come back wrong —
    /// silently continuing would just delay the disconnect until the
    /// first JoinGame frame hit the still-in-Login-state client.
    async fn run_configuration_phase(&mut self) -> Result<(), ConnectionError> {
        use bytes::BytesMut;
        use kojacoord_protocol::codec::{Decode, Encode};
        use kojacoord_protocol::types::VarInt;
        use kojacoord_protocol::versions::v1_20_x::config::ClientboundFinishConfiguration;

        let proto = self.protocol_version;
        let threshold = self.compression_threshold;

        // 1. Client → proxy: ServerboundLoginAcknowledged.
        let expected_login_ack = crate::packet_ids::sb_login(proto, "ServerboundLoginAcknowledged");
        let raw = crate::packet_io::read_packet(&mut *self.stream, threshold).await?;
        let mut cursor = raw;
        let pkt_id = VarInt::decode(&mut cursor)
            .map_err(ConnectionError::Protocol)?
            .0 as u8;
        if pkt_id != expected_login_ack {
            tracing::warn!(
                pkt_id,
                expected = expected_login_ack,
                "limbo config phase: expected LoginAcknowledged, got something else"
            );
            // Don't bail — some launchers ship out-of-order packets;
            // continuing into FinishConfiguration usually resyncs the
            // client. If it doesn't, the next read will time out and
            // the limbo's keepalive loop catches it.
        }

        // 2. Proxy → client: ClientboundFinishConfiguration.
        let id_finish = crate::packet_ids::cb_config(proto, "ClientboundFinishConfiguration");
        if id_finish == 0xFF {
            tracing::warn!(
                proto,
                "limbo config phase: no FinishConfiguration id in registry — skipping"
            );
            return Ok(());
        }
        let mut body = BytesMut::new();
        ClientboundFinishConfiguration {}
            .encode(&mut body)
            .map_err(ConnectionError::Protocol)?;
        crate::packet_io::write_typed_packet(&mut *self.stream, id_finish, &body, proto, threshold)
            .await?;

        // 3. Client → proxy: ServerboundAcknowledgeFinishConfiguration.
        let expected_ack = crate::packet_ids::sb_config(proto, "AcknowledgeFinishConfiguration");
        let raw = crate::packet_io::read_packet(&mut *self.stream, threshold).await?;
        let mut cursor = raw;
        let pkt_id = VarInt::decode(&mut cursor)
            .map_err(ConnectionError::Protocol)?
            .0 as u8;
        if pkt_id != expected_ack {
            tracing::warn!(
                pkt_id,
                expected = expected_ack,
                "limbo config phase: expected AcknowledgeFinishConfiguration, got something else"
            );
        }
        Ok(())
    }

    async fn send_login_play(&mut self) -> Result<(), ConnectionError> {
        let built = self
            .packets
            .join_game(self.protocol_version, LIMBO_WORLD_NAME);
        if built.is_none() && self.protocol_version < 759 && self.protocol_version >= 755 {
            tracing::warn!(
                protocol = self.protocol_version,
                "Limbo does not support 1.17/1.18 NBT login shape; skipping JoinGame"
            );
        }
        self.send_built(built).await
    }

    pub async fn send_respawn(&mut self) -> Result<(), ConnectionError> {
        tracing::debug!("Sending Respawn packet to transition client out of limbo");
        let built = self
            .packets
            .respawn(self.protocol_version, LIMBO_WORLD_NAME);
        self.send_built(built).await
    }

    async fn send_plugin_brand(&mut self) -> Result<(), ConnectionError> {
        let brand: &str = match self.ml_kind {
            modloader::ModloaderKind::Fml1 | modloader::ModloaderKind::Fml2 => "fml,bukkit",
            modloader::ModloaderKind::Fml3 => "forge",
            modloader::ModloaderKind::NeoForge => "neoforge",
            modloader::ModloaderKind::Fabric => "fabric",
            // Quilt clients accept "fabric" as the brand without complaint —
            // QSL piggybacks on Fabric's brand handshake.
            modloader::ModloaderKind::Quilt => "quilt",
            modloader::ModloaderKind::Unknown | modloader::ModloaderKind::Vanilla => "Kojacoord",
        };
        let built = self.packets.brand(self.protocol_version, brand);
        self.send_built(built).await
    }

    /// Tell an FML1 (1.6/1.7/1.12 Forge) client to abandon the FML
    /// handshake. The proxy is not Forge — without this the client
    /// waits forever for `ServerHello` and times out. Picks the
    /// pre-netty wire format for 1.6.x clients automatically.
    async fn send_fml1_handshake_reset(&mut self) -> Result<(), ConnectionError> {
        let plugin_msg_id = crate::packet_ids::cb_plugin_message_id(self.protocol_version);
        let frame =
            modloader::build_fml1_handshake_reset_for_proto(self.protocol_version, plugin_msg_id);
        if crate::packet_io::is_pre_netty_proto(self.protocol_version) {
            crate::packet_io::write_legacy_bytes(&mut *self.stream, &frame).await
        } else {
            let buf = bytes::BytesMut::from(&frame[..]);
            self.write_frame(&buf).await
        }
    }

    async fn send_player_abilities(&mut self) -> Result<(), ConnectionError> {
        let built = self.packets.player_abilities(self.protocol_version);
        self.send_built(built).await
    }

    async fn send_held_item_change(&mut self) -> Result<(), ConnectionError> {
        let built = self.packets.held_item_change(self.protocol_version);
        self.send_built(built).await
    }

    async fn send_player_position(&mut self, teleport_id: i32) -> Result<(), ConnectionError> {
        let pos = PlayerPos {
            x: LIMBO_X,
            y: LIMBO_Y,
            z: LIMBO_Z,
            yaw: 0.0,
            pitch: 0.0,
        };
        let built = self
            .packets
            .player_position(self.protocol_version, pos, teleport_id);
        self.send_built(built).await
    }

    async fn send_limbo_chat(&mut self) -> Result<(), ConnectionError> {
        const MSG_JSON: &str = r#"{"text":"The server is currently offline. You have been placed in limbo and will be connected automatically when it comes back online.","color":"yellow"}"#;
        let built = self.packets.chat(self.protocol_version, MSG_JSON);
        self.send_built(built).await
    }

    async fn send_note_sound(&mut self) -> Result<(), ConnectionError> {
        let pos = SoundParams {
            x: LIMBO_X,
            y: LIMBO_Y,
            z: LIMBO_Z,
            volume: 1.0,
            pitch: 1.0,
        };
        let built = self.packets.note_sound(self.protocol_version, pos);
        self.send_built(built).await
    }

    async fn send_bossbar_add(&mut self) -> Result<(), ConnectionError> {
        let title = r#"{"text":"Waiting for server...","color":"yellow"}"#;
        let uuid = Uuid::parse_str(BOSSBAR_UUID).unwrap();
        let built = self.packets.bossbar_add(self.protocol_version, uuid, title);
        self.send_built(built).await
    }

    async fn send_bossbar_remove(&mut self) -> Result<(), ConnectionError> {
        let uuid = Uuid::parse_str(BOSSBAR_UUID).unwrap();
        let built = self.packets.bossbar_remove(self.protocol_version, uuid);
        self.send_built(built).await
    }

    async fn send_keepalive(&mut self, id: i64) -> Result<(), ConnectionError> {
        tracing::trace!(keepalive_id = id, "Building KeepAlive packet");
        let built = self.packets.keepalive(self.protocol_version, id);
        self.send_built(built).await
    }

    async fn try_connect_backend(&self) -> Option<TcpStream> {
        let username = self.session.read().await.username.clone();

        let backend = match &self.target_server {
            Some(name) => {
                let b = self.state.server_registry.get(name)?;
                if !b.is_online() {
                    return None;
                }
                b
            },
            None => self.state.routing.select(&self.state.server_registry)?,
        };
        tracing::debug!(
            player = %username,
            server = %backend.name,
            address = %backend.address,
            "Trying backend connection (limbo poll)"
        );

        let result = if let Some(pool) = &backend.connection_pool {
            match tokio::time::timeout(Duration::from_millis(1500), pool.acquire()).await {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "pool acquire timed out",
                )),
            }
        } else {
            match tokio::time::timeout(
                Duration::from_millis(1500),
                TcpStream::connect(&backend.address),
            )
            .await
            {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection timed out",
                )),
            }
        };

        match result {
            Ok(stream) => {
                tracing::info!(
                    player = %username,
                    server = %backend.name,
                    "Backend connection successful (limbo)"
                );
                Some(stream)
            },
            Err(e) => {
                tracing::trace!(
                    player = %username,
                    server = %backend.name,
                    error = %e,
                    "Backend connection failed (limbo)"
                );
                None
            },
        }
    }

    async fn write_frame(&mut self, payload: &bytes::BytesMut) -> Result<(), ConnectionError> {
        crate::packet_io::write_packet(&mut *self.stream, payload, self.compression_threshold).await
    }

    async fn read_and_discard(&mut self) -> Result<(), ConnectionError> {
        crate::packet_io::read_frame(&mut *self.stream).await?;
        Ok(())
    }
}
