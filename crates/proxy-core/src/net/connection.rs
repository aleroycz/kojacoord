use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use uuid::Uuid;

use aes::cipher::BlockEncrypt;
use aes::Aes128;
use bytes::{Bytes, BytesMut};
use kojacoord_protocol::ProtocolVersion;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use kojacoord_protocol::{
    codec::{Decode, Encode, PacketId},
    types::VarInt,
    versions::v1_8::{
        handshake::ServerboundHandshake,
        login::ServerboundLoginStart,
        status::{ClientboundPongResponse, ClientboundStatusResponse, ServerboundPingRequest},
    },
};

use crate::{
    error::ConnectionError,
    modloader,
    packet_builder::build_system_message_packet,
    packet_ids::{cb_config, cb_login, cb_play, nearest, sb_config, sb_login, REGISTRY},
    packet_io::{read_varint, NO_COMPRESSION},
    proxy::ProxyState,
    relay::PacketRelay,
    session::{ConnectionState, PlayerSession, SharedSession},
};

use kojacoord_auth::{forwarding::bungeecord_suffix, AuthEvent, AuthOutbound};
use kojacoord_protocol::registry::{Direction, ProtocolState};

struct Cfb8State {
    cipher: Aes128,
    sr: [u8; 16],
}

impl Cfb8State {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        use aes::cipher::KeyInit;
        Self {
            cipher: Aes128::new(key.into()),
            sr: *iv,
        }
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        use aes::cipher::generic_array::GenericArray;
        for byte in data.iter_mut() {
            let mut block = GenericArray::clone_from_slice(&self.sr);
            self.cipher.encrypt_block(&mut block);
            let ks = block[0];
            *byte ^= ks;
            let ct = *byte;
            self.sr.rotate_left(1);
            self.sr[15] = ct;
        }
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        use aes::cipher::generic_array::GenericArray;
        for byte in data.iter_mut() {
            let ct = *byte;
            let mut block = GenericArray::clone_from_slice(&self.sr);
            self.cipher.encrypt_block(&mut block);
            let ks = block[0];
            *byte ^= ks;
            self.sr.rotate_left(1);
            self.sr[15] = ct;
        }
    }
}

pub struct EncryptedStream {
    inner: TcpStream,
    enc: Cfb8State,
    dec: Cfb8State,

    write_buf: BytesMut,
}

impl EncryptedStream {
    pub fn new(stream: TcpStream, key: &[u8]) -> Self {
        let key: &[u8; 16] = key.try_into().expect("AES key must be 16 bytes");
        Self {
            inner: stream,
            enc: Cfb8State::new(key, key),
            dec: Cfb8State::new(key, key),
            write_buf: BytesMut::new(),
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.write_buf.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write encrypted bytes to socket",
                    )));
                },
                Poll::Ready(Ok(n)) => {
                    let _ = self.write_buf.split_to(n);
                },
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for EncryptedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let after = buf.filled().len();
        if after > before {
            self.dec.decrypt(&mut buf.filled_mut()[before..after]);
        }
        result
    }
}

impl AsyncWrite for EncryptedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        std::task::ready!(this.poll_drain(cx))?;

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut encrypted = buf.to_vec();
        this.enc.encrypt(&mut encrypted);
        this.write_buf.extend_from_slice(&encrypted);

        match this.poll_drain(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),

            _ => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[allow(clippy::large_enum_variant)]
pub enum McStream {
    Empty,
    Plain(TcpStream),
    Encrypted(EncryptedStream),
}

impl McStream {
    pub fn enable_encryption(&mut self, key: &[u8]) {
        let old = std::mem::replace(self, McStream::Empty);
        *self = match old {
            McStream::Plain(stream) => McStream::Encrypted(EncryptedStream::new(stream, key)),
            McStream::Encrypted(stream) => McStream::Encrypted(stream),
            McStream::Empty => unreachable!(),
        };
    }
}

impl AsyncRead for McStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            McStream::Empty => Poll::Ready(Ok(())),
            McStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            McStream::Encrypted(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for McStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            McStream::Empty => Poll::Ready(Ok(buf.len())),
            McStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            McStream::Encrypted(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            McStream::Empty => Poll::Ready(Ok(())),
            McStream::Plain(s) => Pin::new(s).poll_flush(cx),
            McStream::Encrypted(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            McStream::Empty => Poll::Ready(Ok(())),
            McStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            McStream::Encrypted(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub async fn connect_with_timeout(addr: &SocketAddr) -> Result<TcpStream, std::io::Error> {
    match tokio::time::timeout(
        tokio::time::Duration::from_millis(1500),
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "connection timed out",
        )),
    }
}

pub struct ClientConnection {
    stream: McStream,
    addr: SocketAddr,
    state: Arc<ProxyState>,
    conn_state: ConnectionState,
    protocol_version: u32,
    compression_threshold: i32,
    ml_session: modloader::ModloaderSession,
}

impl ClientConnection {
    pub fn new(stream: TcpStream, addr: SocketAddr, state: Arc<ProxyState>) -> Self {
        Self {
            stream: McStream::Plain(stream),
            addr,
            state,
            conn_state: ConnectionState::Handshaking,
            protocol_version: 0,
            compression_threshold: NO_COMPRESSION,
            ml_session: modloader::ModloaderSession::new(),
        }
    }

    pub async fn run(mut self) -> Result<(), ConnectionError> {
        self.state.metrics.record_connection();

        let handshake = self
            .read_packet::<ServerboundHandshake>()
            .await
            .inspect_err(|_| {
                self.state.metrics.record_failed_connection();
            })?;

        self.protocol_version = handshake.protocol_version.0 as u32;

        self.ml_session.kind = modloader::detect_from_address(&handshake.server_address);
        tracing::debug!(
            kind    = ?self.ml_session.kind,
            address = %handshake.server_address,
            "modloader detected from client handshake"
        );

        let result = match handshake.next_state.0 {
            1 => {
                self.conn_state = ConnectionState::Status;
                self.handle_status().await
            },
            2 => {
                self.conn_state = ConnectionState::Login;
                self.handle_login(handshake.server_address)
                    .await
                    .map(|_| ())
            },
            _ => Err(ConnectionError::Closed),
        };

        self.state.metrics.record_disconnection();
        if result.is_err() {
            self.state.metrics.record_failed_connection();
        }
        result
    }

    async fn read_packet<T: Decode + PacketId>(&mut self) -> Result<T, ConnectionError> {
        let mut bytes =
            crate::packet_io::read_packet(&mut self.stream, self.compression_threshold).await?;
        let _id = VarInt::decode(&mut bytes)?;
        Ok(T::decode(&mut bytes)?)
    }

    async fn write_packet<T: Encode + PacketId>(
        &mut self,
        packet: &T,
    ) -> Result<(), ConnectionError> {
        let pid = T::packet_id(self.protocol_version) as i32;
        if pid == 0xFF {
            return Ok(());
        }
        let mut payload = BytesMut::new();
        VarInt(pid).encode(&mut payload)?;
        packet.encode(&mut payload)?;
        crate::packet_io::write_packet(&mut self.stream, &payload, self.compression_threshold)
            .await?;
        Ok(())
    }

    /// Read a raw framed packet from the client stream, returning the raw
    /// payload bytes (including the packet-id varint).
    async fn read_raw_packet_bytes(&mut self) -> Result<Bytes, ConnectionError> {
        crate::packet_io::read_packet(&mut self.stream, self.compression_threshold).await
    }

    async fn handle_status(&mut self) -> Result<(), ConnectionError> {
        let _len = read_varint(&mut self.stream).await?;
        let _id = read_varint(&mut self.stream).await?;

        let (online_count, sample) = {
            let sessions = self.state.sessions.read().await;
            let count = sessions.len();
            let server_lore = &self.state.config.listeners.server_lore;

            let mut sample: Vec<serde_json::Value> = sessions
                .values()
                .take(12)
                .filter_map(|s| s.try_read().ok())
                .map(|s| {
                    let mut player_json = serde_json::json!({
                        "name": s.username,
                        "id":   s.uuid.hyphenated().to_string(),
                    });

                    if let Some(lore) = server_lore {
                        player_json["lore"] = serde_json::json!(lore);
                    }

                    player_json
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

        let description = if let Some(ref motd_json) = self.state.config.listeners.motd_json {
            motd_json.clone()
        } else {
            serde_json::json!({ "text": &self.state.config.listeners.motd })
        };

        let json = serde_json::json!({
            "version": { "name": "Koja", "protocol": self.protocol_version },
            "players": {
                "max":    self.state.config.proxy.max_players,
                "online": online_count,
                "sample": sample,
            },
            "description": description,
        })
        .to_string();

        self.write_packet(&ClientboundStatusResponse {
            json_response: json,
        })
        .await?;
        let ping = self.read_packet::<ServerboundPingRequest>().await?;
        self.write_packet(&ClientboundPongResponse {
            payload: ping.payload,
        })
        .await?;
        Ok(())
    }

    async fn handle_login(
        &mut self,
        original_host: String,
    ) -> Result<SharedSession, ConnectionError> {
        let login_start = self.read_packet::<ServerboundLoginStart>().await?;
        let username = login_start.username.clone();

        let client_uuid = if self.protocol_version >= 761 {
            let mut cursor = self.read_raw_packet_bytes().await?;

            let _ = VarInt::decode(&mut cursor).ok();
            let _ = String::decode(&mut cursor).ok();

            let uuid_decode_err = || ConnectionError::Auth("failed to decode client UUID".into());

            if self.protocol_version <= 763 {
                let has_uuid = bool::decode(&mut cursor).unwrap_or(false);
                if has_uuid {
                    let hi = i64::decode(&mut cursor).ok().ok_or_else(uuid_decode_err)? as u64;
                    let lo = i64::decode(&mut cursor).ok().ok_or_else(uuid_decode_err)? as u64;
                    Some(uuid::Uuid::from_u64_pair(hi, lo))
                } else {
                    None
                }
            } else {
                let hi = i64::decode(&mut cursor).ok().ok_or_else(uuid_decode_err)? as u64;
                let lo = i64::decode(&mut cursor).ok().ok_or_else(uuid_decode_err)? as u64;
                Some(uuid::Uuid::from_u64_pair(hi, lo))
            }
        } else {
            None
        };

        let is_offline_mode = !self.state.config.proxy.online_mode;

        // In offline mode, generate/retrieve UUID from database if not provided by client
        let final_uuid = if is_offline_mode {
            if let Some(db) = &self.state.db {
                match db.get_or_create_offline_uuid(&username).await {
                    Ok(uuid) => {
                        tracing::debug!(
                            "Generated/retrieved offline UUID {} for username {}",
                            uuid,
                            username
                        );
                        Some(uuid)
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to get offline UUID for {}, using client UUID or generating random", username);
                        client_uuid.or_else(|| Some(uuid::Uuid::new_v4()))
                    },
                }
            } else {
                tracing::warn!("No database available for offline UUID generation, using client UUID or random");
                client_uuid.or_else(|| Some(uuid::Uuid::new_v4()))
            }
        } else {
            client_uuid
        };

        fn client_gone(e: &ConnectionError) -> bool {
            matches!(e, ConnectionError::Closed | ConnectionError::Io(_))
        }

        let mut auth_pipeline = self
            .state
            .auth_pipeline_config
            .build()
            .map_err(|e| ConnectionError::Auth(e.to_string()))?;

        let client_ip = self.addr.ip();

        let outbound = auth_pipeline
            .process(
                AuthEvent::LoginStart {
                    username: username.clone(),
                    client_uuid: final_uuid,
                },
                client_ip,
            )
            .await;

        let mut encryption_requested = false;

        for event in outbound {
            match event {
                AuthOutbound::EncryptionRequest {
                    server_id: _,
                    public_key,
                    verify_token,
                } => {
                    self.send_encryption_request(&public_key, &verify_token)
                        .await?;
                    encryption_requested = true;
                },
                AuthOutbound::SetCompression { threshold } => {
                    self.send_set_compression_with_threshold(threshold).await?;
                    self.compression_threshold = threshold;
                },
                AuthOutbound::LoginSuccess {
                    uuid,
                    username,
                    properties,
                } => {
                    return self
                        .finalise_login(uuid, username, properties, original_host, &client_gone)
                        .await;
                },
                AuthOutbound::LoginDisconnect { reason } => {
                    let _ = self.send_disconnect_login(&reason).await;
                    return Err(ConnectionError::Auth(reason));
                },
                AuthOutbound::EnableEncryption { shared_secret } => {
                    tracing::debug!("enabling AES/CFB8 encryption on client stream");
                    self.stream.enable_encryption(&shared_secret);
                },
            }
        }

        if !encryption_requested {
            return Err(ConnectionError::Auth("Authentication failed".into()));
        }

        let (enc_shared_secret, enc_verify_token) = self.recv_encryption_response().await?;

        let outbound = auth_pipeline
            .process(
                AuthEvent::EncryptionResponse {
                    shared_secret_enc: enc_shared_secret,
                    verify_token_enc: enc_verify_token,
                },
                client_ip,
            )
            .await;

        for event in outbound {
            match event {
                AuthOutbound::SetCompression { threshold } => {
                    self.send_set_compression_with_threshold(threshold).await?;
                    self.compression_threshold = threshold;
                },
                AuthOutbound::LoginSuccess {
                    uuid,
                    username,
                    properties,
                } => {
                    return self
                        .finalise_login(uuid, username, properties, original_host, &client_gone)
                        .await;
                },
                AuthOutbound::LoginDisconnect { reason } => {
                    let _ = self.send_disconnect_login(&reason).await;
                    return Err(ConnectionError::Auth(reason));
                },
                AuthOutbound::EnableEncryption { shared_secret } => {
                    tracing::debug!("enabling AES/CFB8 encryption on client stream");
                    self.stream.enable_encryption(&shared_secret);
                },
                _ => {},
            }
        }

        Err(ConnectionError::Auth("Authentication failed".into()))
    }

    async fn finalise_login(
        &mut self,
        uuid: uuid::Uuid,
        username: String,
        properties: Vec<kojacoord_auth::ProfileProperty>,
        original_host: String,
        client_gone: &impl Fn(&ConnectionError) -> bool,
    ) -> Result<SharedSession, ConnectionError> {
        // Reject banned players before completing login. Best-effort: a DB error
        // never blocks a legitimate login.
        if let Some(db) = &self.state.db {
            if let Ok(Some(ban)) = db.active_ban(uuid).await {
                let reason = serde_json::json!({
                    "text": format!("You are banned: {}", ban.reason),
                    "color": "red"
                })
                .to_string();
                let _ = self.send_disconnect_login(&reason).await;
                tracing::debug!(username = %username, reason = %ban.reason, "rejected banned player");
                return Err(ConnectionError::Auth(format!("banned: {}", ban.reason)));
            }
        }

        self.send_login_success(uuid, &username, &properties)
            .await?;

        // Player lifecycle: create the row on first join, refresh username and
        // last_seen otherwise, and read back the persisted rank. Best-effort — a
        // database outage must not block login, so failures default to "PLAYER".
        let rank = match &self.state.db {
            Some(db) => match db.upsert_player_on_join(uuid, &username).await {
                Ok(rank) => rank,
                Err(e) => {
                    tracing::warn!(username = %username, error = %e, "failed to persist player record");
                    "PLAYER".to_owned()
                },
            },
            None => "PLAYER".to_owned(),
        };

        let session = Arc::new(RwLock::new(PlayerSession {
            uuid,
            username: username.clone(),
            client_ip: self.addr.ip(),
            protocol_version: self.protocol_version,
            state: ConnectionState::Play,
            current_server: None,
            properties: properties
                .iter()
                .map(|p| kojacoord_auth::ProfileProperty {
                    name: p.name.clone(),
                    value: p.value.clone(),
                    signature: p.signature.clone(),
                })
                .collect(),
            locale: None,
            view_distance: None,
            rank,
        }));

        {
            let mut sessions = self.state.sessions.write().await;
            sessions.insert(uuid, session.clone());
        }

        let backend_result = self
            .connect_to_backend(&username, session.clone(), &original_host, uuid)
            .await;

        let (backend, backend_threshold) = match backend_result {
            Ok(b) => b,
            Err(e) => {
                {
                    let mut sessions = self.state.sessions.write().await;
                    sessions.remove(&uuid);
                }
                if !client_gone(&e) {
                    let _ = self
                        .send_play_disconnect(
                            r#"{"text":"Could not connect to any backend server.","color":"red"}"#,
                        )
                        .await;
                }
                return Err(e);
            },
        };

        // Relay loop. A normal relay session ends in `Disconnected`; a
        // selector/command Connect ends in `Switch`, where we move the player to
        // the requested backend via limbo and relay against the new connection
        // without ever dropping the client.
        let mut backend = backend;
        let mut backend_threshold = backend_threshold;
        let result = loop {
            match self
                .relay(backend, session.clone(), backend_threshold)
                .await
            {
                Ok(crate::relay::RelayExit::Disconnected) => break Ok(()),
                Ok(crate::relay::RelayExit::Switch {
                    client_stream,
                    target,
                }) => {
                    // Restore the client stream the relay handed back.
                    self.stream = client_stream;
                    match self
                        .switch_to_server(&target, session.clone(), &username, &original_host, uuid)
                        .await
                    {
                        Ok((new_backend, new_threshold)) => {
                            backend = new_backend;
                            backend_threshold = new_threshold;
                            continue;
                        },
                        Err(e) => {
                            tracing::warn!(target = %target, err = %e, "live switch failed");
                            if !client_gone(&e) {
                                let _ = self
                                    .send_play_disconnect(
                                        r#"{"text":"Failed to connect to that server.","color":"red"}"#,
                                    )
                                    .await;
                            }
                            break Err(e);
                        },
                    }
                },
                Err(e) => break Err(e),
            }
        };

        {
            let mut sessions = self.state.sessions.write().await;
            sessions.remove(&uuid);
        }

        if let Err(ref e) = result {
            if !client_gone(e) {
                let msg = format!(r#"{{"text":"{}","color":"red"}}"#, e);
                let _ = self.send_play_disconnect(&msg).await;
            }
        }

        result?;
        Ok(session)
    }

    /// Move an in-play player to `target` without dropping the connection:
    /// reset the client into limbo (which transitions its world), then connect,
    /// handshake and complete login against the chosen backend. Returns the new
    /// backend stream and its compression threshold for the next relay leg.
    async fn switch_to_server(
        &mut self,
        target: &str,
        session: SharedSession,
        username: &str,
        original_host: &str,
        uuid: Uuid,
    ) -> Result<(TcpStream, i32), ConnectionError> {
        let props = session.read().await.properties.clone();

        // Hold the player in limbo while we (re)connect. The limbo handler sends a
        // fresh JoinGame + Respawn, which resets the client's world so the new

        let mut limbo = crate::limbo::LimboHandler::new(
            &mut self.stream,
            Arc::clone(&self.state),
            session.clone(),
            self.protocol_version,
            self.compression_threshold,
            self.ml_session.kind,
        );
        limbo.set_target(target.to_owned());
        let mut backend = limbo.run().await?;

        let server = self.state.server_registry.get(target);
        let mode = self
            .effective_forwarding_mode(server.as_ref().and_then(|b| b.forwarding_override.clone()));
        let backend_type = server
            .as_ref()
            .map(|b| b.backend_type.clone())
            .unwrap_or_default();

        self.send_backend_handshake(
            &mut backend,
            original_host,
            username,
            uuid,
            &props,
            &mode,
            &backend_type,
        )
        .await?;
        let backend_threshold = self.complete_backend_login(&mut backend).await?;

        if let Some(b) = self.state.server_registry.get(target) {
            b.player_count.fetch_add(1, Ordering::Relaxed);
        }
        session.write().await.current_server = Some(target.to_owned());
        tracing::debug!(username = %username, server = %target, "switched player to backend");

        Ok((backend, backend_threshold))
    }

    pub async fn send_set_compression(&mut self) -> Result<(), ConnectionError> {
        self.send_set_compression_with_threshold(self.state.config.proxy.compression_threshold)
            .await
    }

    async fn send_set_compression_with_threshold(
        &mut self,
        threshold: i32,
    ) -> Result<(), ConnectionError> {
        let proto = self.protocol_version;
        let ver = nearest(proto);
        let pid = cb_login(proto, "ClientboundSetCompression");
        match ver {
            ProtocolVersion::V1_6_4 | ProtocolVersion::V1_7_10 | ProtocolVersion::V1_8 => {
                use kojacoord_protocol::versions::v1_8::login::ClientboundSetCompression;
                self.write_login_packet(
                    ClientboundSetCompression {
                        threshold: VarInt(threshold),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_12_2 => {
                use kojacoord_protocol::versions::v1_12_2::login::ClientboundSetCompression;
                self.write_login_packet(
                    ClientboundSetCompression {
                        threshold: VarInt(threshold),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_16_5 => {
                use kojacoord_protocol::versions::v1_16_5::login::ClientboundSetCompression;
                self.write_login_packet(
                    ClientboundSetCompression {
                        threshold: VarInt(threshold),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_19_4 => {
                use kojacoord_protocol::versions::v1_19_4::login::ClientboundSetCompression;
                self.write_login_packet(
                    ClientboundSetCompression {
                        threshold: VarInt(threshold),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_20_4 => {
                use kojacoord_protocol::versions::v1_20_4::login::ClientboundSetCompression;
                self.write_login_packet(
                    ClientboundSetCompression {
                        threshold: VarInt(threshold),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_21 => {
                use kojacoord_protocol::versions::v1_21::login::ClientboundSetCompression;
                self.write_login_packet(
                    ClientboundSetCompression {
                        threshold: VarInt(threshold),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::Unknown(v) => {
                tracing::error!(protocol = ?v, "Unknown protocol version for set compression");
                Err(ConnectionError::Protocol(
                    kojacoord_protocol::ProtocolError::VarIntOverflow(0),
                ))
            },
        }
    }

    async fn send_login_success(
        &mut self,
        uuid: Uuid,
        username: &str,
        properties: &[kojacoord_auth::ProfileProperty],
    ) -> Result<(), ConnectionError> {
        let proto = self.protocol_version;
        let ver = nearest(proto);
        let pid = cb_login(proto, "ClientboundLoginSuccess");
        tracing::debug!(
            username,
            uuid = %uuid,
            protocol = proto,
            packet_id = pid,
            "sending LoginSuccess"
        );
        match ver {
            ProtocolVersion::V1_6_4 => {
                use kojacoord_protocol::versions::v1_6_4::login::LoginRequestS2C;
                self.write_login_packet(
                    LoginRequestS2C {
                        entity_id: 0,
                        level_type: "default".to_string(),
                        game_mode: 0,
                        dimension: 0,
                        difficulty: 0,
                        world_height: 250,
                        max_players: 20,
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_7_10 => {
                use kojacoord_protocol::versions::v1_7_10::login::ClientboundLoginSuccess;
                self.write_login_packet(
                    ClientboundLoginSuccess {
                        uuid,
                        username: username.to_owned(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_8 => {
                use kojacoord_protocol::versions::v1_8::login::ClientboundLoginSuccess;
                self.write_login_packet(
                    ClientboundLoginSuccess {
                        uuid,
                        username: username.to_owned(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_12_2 => {
                use kojacoord_protocol::versions::v1_12_2::login::{
                    ClientboundLoginSuccess, ProfileProperty,
                };
                self.write_login_packet(
                    ClientboundLoginSuccess {
                        uuid,
                        username: username.to_string(),
                        properties: properties
                            .iter()
                            .map(|p| ProfileProperty {
                                name: p.name.clone(),
                                value: p.value.clone(),
                                signature: p.signature.clone(),
                            })
                            .collect(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_19_4 => {
                use kojacoord_protocol::versions::v1_19_4::login::{
                    ClientboundLoginSuccess, ProfileProperty,
                };
                self.write_login_packet(
                    ClientboundLoginSuccess {
                        uuid,
                        username: username.to_owned(),
                        properties: properties
                            .iter()
                            .map(|p| ProfileProperty {
                                name: p.name.clone(),
                                value: p.value.clone(),
                                signature: p.signature.clone(),
                            })
                            .collect(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_16_5 => {
                use kojacoord_protocol::versions::v1_16_5::login::{
                    ClientboundLoginSuccess, ProfileProperty,
                };
                self.write_login_packet(
                    ClientboundLoginSuccess {
                        uuid,
                        username: username.to_owned(),
                        properties: properties
                            .iter()
                            .map(|p| ProfileProperty {
                                name: p.name.clone(),
                                value: p.value.clone(),
                                signature: p.signature.clone(),
                            })
                            .collect(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_20_4 => {
                use kojacoord_protocol::versions::v1_20_4::login::{
                    ClientboundLoginSuccess, ProfileProperty,
                };
                self.write_login_packet(
                    ClientboundLoginSuccess {
                        uuid,
                        username: username.to_owned(),
                        properties: properties
                            .iter()
                            .map(|p| ProfileProperty {
                                name: p.name.clone(),
                                value: p.value.clone(),
                                signature: p.signature.clone(),
                            })
                            .collect(),
                        strict_error_handling: true,
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_21 => {
                use kojacoord_protocol::versions::v1_21::login::{
                    ClientboundLoginSuccess, ProfileProperty,
                };
                self.write_login_packet(
                    ClientboundLoginSuccess {
                        uuid,
                        username: username.to_owned(),
                        properties: properties
                            .iter()
                            .map(|p| ProfileProperty {
                                name: p.name.clone(),
                                value: p.value.clone(),
                                signature: p.signature.clone(),
                            })
                            .collect(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::Unknown(v) => {
                tracing::error!(protocol = ?v, "Unknown protocol version for login success");
                Err(ConnectionError::Protocol(
                    kojacoord_protocol::ProtocolError::VarIntOverflow(0),
                ))
            },
        }
    }

    async fn send_encryption_request(
        &mut self,
        der_public_key: &[u8],
        verify_token: &[u8],
    ) -> Result<(), ConnectionError> {
        let proto = self.protocol_version;
        let ver = nearest(proto);
        let pid = cb_login(proto, "ClientboundEncryptionRequest");
        match ver {
            ProtocolVersion::V1_6_4 => Ok(()),
            ProtocolVersion::V1_7_10 => {
                use kojacoord_protocol::versions::v1_7_10::login::ClientboundEncryptionRequest;
                self.write_login_packet(
                    ClientboundEncryptionRequest {
                        server_id: "".to_string(),
                        public_key: der_public_key.to_vec(),
                        verify_token: verify_token.to_vec(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_8 => {
                use kojacoord_protocol::versions::v1_8::login::ClientboundEncryptionRequest;
                self.write_login_packet(
                    ClientboundEncryptionRequest {
                        server_id: "".to_string(),
                        public_key: der_public_key.to_vec(),
                        verify_token: verify_token.to_vec(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_12_2 => {
                use kojacoord_protocol::versions::v1_12_2::login::ClientboundEncryptionRequest;
                self.write_login_packet(
                    ClientboundEncryptionRequest {
                        server_id: "".to_string(),
                        public_key: der_public_key.to_vec(),
                        verify_token: verify_token.to_vec(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_16_5 => {
                use kojacoord_protocol::versions::v1_16_5::login::ClientboundEncryptionRequest;
                self.write_login_packet(
                    ClientboundEncryptionRequest {
                        server_id: "".to_string(),
                        public_key: der_public_key.to_vec(),
                        verify_token: verify_token.to_vec(),
                        should_authenticate: true,
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_19_4 => {
                use kojacoord_protocol::versions::v1_19_4::login::ClientboundEncryptionRequest;
                self.write_login_packet(
                    ClientboundEncryptionRequest {
                        server_id: "".to_string(),
                        public_key: der_public_key.to_vec(),
                        verify_token: verify_token.to_vec(),
                        should_authenticate: true,
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_20_4 => {
                use kojacoord_protocol::versions::v1_20_4::login::ClientboundEncryptionRequest;
                self.write_login_packet(
                    ClientboundEncryptionRequest {
                        server_id: "".to_string(),
                        public_key: der_public_key.to_vec(),
                        verify_token: verify_token.to_vec(),
                        should_authenticate: true,
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_21 => {
                use kojacoord_protocol::versions::v1_21::login::ClientboundEncryptionRequest;
                self.write_login_packet(
                    ClientboundEncryptionRequest {
                        server_id: "".to_string(),
                        public_key: der_public_key.to_vec(),
                        verify_token: verify_token.to_vec(),
                        should_authenticate: true,
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::Unknown(v) => {
                tracing::error!(protocol = ?v, "Unknown protocol version for encryption request");
                Err(ConnectionError::Protocol(
                    kojacoord_protocol::ProtocolError::VarIntOverflow(0),
                ))
            },
        }
    }

    async fn recv_encryption_response(&mut self) -> Result<(Vec<u8>, Vec<u8>), ConnectionError> {
        let mut bytes =
            crate::packet_io::read_packet(&mut self.stream, self.compression_threshold).await?;
        let _id = VarInt::decode(&mut bytes)?;
        let ss_len = VarInt::decode(&mut bytes)?.0 as usize;
        let ss: Vec<u8> = bytes.split_to(ss_len).to_vec();
        let vt_len = VarInt::decode(&mut bytes)?.0 as usize;
        let vt: Vec<u8> = bytes.split_to(vt_len).to_vec();
        Ok((ss, vt))
    }

    async fn send_disconnect_login(&mut self, reason_json: &str) -> Result<(), ConnectionError> {
        let proto = self.protocol_version;
        let ver = nearest(proto);
        let pid = cb_login(proto, "ClientboundLoginDisconnect");
        match ver {
            ProtocolVersion::V1_6_4 => {
                use kojacoord_protocol::versions::v1_7_10::login::ClientboundLoginDisconnect;
                self.write_login_packet(
                    ClientboundLoginDisconnect {
                        reason: reason_json.to_owned(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_7_10 => {
                use kojacoord_protocol::versions::v1_7_10::login::ClientboundLoginDisconnect;
                self.write_login_packet(
                    ClientboundLoginDisconnect {
                        reason: reason_json.to_owned(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_8 => {
                use kojacoord_protocol::versions::v1_8::login::ClientboundLoginDisconnect;
                self.write_login_packet(
                    ClientboundLoginDisconnect {
                        reason: reason_json.to_owned(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_12_2 => {
                use kojacoord_protocol::versions::v1_12_2::login::ClientboundLoginDisconnect;
                self.write_login_packet(
                    ClientboundLoginDisconnect {
                        reason: reason_json.to_owned(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_16_5 => {
                use kojacoord_protocol::versions::v1_16_5::login::ClientboundLoginDisconnect;
                self.write_login_packet(
                    ClientboundLoginDisconnect {
                        reason: reason_json.to_owned(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_19_4 => {
                use kojacoord_protocol::versions::v1_19_4::login::ClientboundLoginDisconnect;
                self.write_login_packet(
                    ClientboundLoginDisconnect {
                        reason: reason_json.to_owned(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_20_4 => {
                use kojacoord_protocol::versions::v1_20_4::login::ClientboundLoginDisconnect;
                self.write_login_packet(
                    ClientboundLoginDisconnect {
                        reason: reason_json.to_owned(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::V1_21 => {
                use kojacoord_protocol::versions::v1_21::login::ClientboundLoginDisconnect;
                self.write_login_packet(
                    ClientboundLoginDisconnect {
                        reason: reason_json.to_owned(),
                    },
                    pid,
                )
                .await
            },
            ProtocolVersion::Unknown(v) => {
                tracing::error!(protocol = ?v, "Unknown protocol version for login disconnect");
                Err(ConnectionError::Protocol(
                    kojacoord_protocol::ProtocolError::VarIntOverflow(0),
                ))
            },
        }
    }

    async fn send_play_disconnect(&mut self, reason_json: &str) -> Result<(), ConnectionError> {
        let proto = self.protocol_version;
        let ver = nearest(proto);
        let pid = cb_play(proto, "ClientboundDisconnect");
        if pid == 0xFF {
            return Ok(());
        }

        let mut payload = BytesMut::new();
        VarInt(pid as i32).encode(&mut payload)?;

        match ver {
            ProtocolVersion::V1_6_4 => {
                use kojacoord_protocol::versions::v1_6_4::play::ClientboundDisconnect;
                let pkt = ClientboundDisconnect {
                    reason: reason_json.to_owned(),
                };
                pkt.encode(&mut payload)?;
            },
            ProtocolVersion::V1_7_10 => {
                use kojacoord_protocol::versions::v1_7_10::play::ClientboundDisconnect;
                let pkt = ClientboundDisconnect {
                    reason: reason_json.to_owned(),
                };
                pkt.encode(&mut payload)?;
            },
            ProtocolVersion::V1_8 => {
                use kojacoord_protocol::versions::v1_8::play::ClientboundDisconnect;
                let pkt = ClientboundDisconnect {
                    reason: reason_json.to_owned(),
                };
                pkt.encode(&mut payload)?;
            },
            ProtocolVersion::V1_12_2 => {
                use kojacoord_protocol::versions::v1_12_2::play::ClientboundDisconnect;
                let pkt = ClientboundDisconnect {
                    reason: reason_json.to_owned(),
                };
                pkt.encode(&mut payload)?;
            },
            ProtocolVersion::V1_16_5 => {
                use kojacoord_protocol::versions::v1_16_5::play::ClientboundDisconnect;
                let pkt = ClientboundDisconnect {
                    reason: reason_json.to_owned(),
                };
                pkt.encode(&mut payload)?;
            },
            ProtocolVersion::V1_19_4 => {
                use kojacoord_protocol::versions::v1_19_4::play::ClientboundDisconnect;
                let pkt = ClientboundDisconnect {
                    reason: reason_json.to_owned(),
                };
                pkt.encode(&mut payload)?;
            },
            ProtocolVersion::V1_20_4 => {
                use kojacoord_protocol::versions::v1_20_4::play::ClientboundDisconnect;
                let pkt = ClientboundDisconnect {
                    reason: reason_json.to_owned(),
                };
                pkt.encode(&mut payload)?;
            },
            ProtocolVersion::V1_21 => {
                use kojacoord_protocol::versions::v1_21::play::ClientboundDisconnect;
                let pkt = ClientboundDisconnect {
                    reason: reason_json.to_owned(),
                };
                pkt.encode(&mut payload)?;
            },
            ProtocolVersion::Unknown(v) => {
                tracing::error!(protocol = ?v, "Unknown protocol version for play disconnect");
                return Err(ConnectionError::Protocol(
                    kojacoord_protocol::ProtocolError::VarIntOverflow(0),
                ));
            },
        }

        crate::packet_io::write_packet(&mut self.stream, &payload, self.compression_threshold)
            .await?;
        Ok(())
    }

    pub async fn send_system_message(&mut self, text: &str) -> Result<(), ConnectionError> {
        let raw = build_system_message_packet(text, self.protocol_version);
        crate::packet_io::write_packet(&mut self.stream, &raw, self.compression_threshold).await?;
        Ok(())
    }

    async fn connect_to_backend(
        &mut self,
        username: &str,
        session: SharedSession,
        original_host: &str,
        uuid: Uuid,
    ) -> Result<(TcpStream, i32), ConnectionError> {
        let props = session.read().await.properties.clone();

        let fwd_host = original_host.to_owned();

        let backend_opt = self.state.routing.select(&self.state.server_registry);

        match backend_opt {
            Some(b) => {
                let stream_result = if let Some(pool) = &b.connection_pool {
                    pool.acquire().await.map_err(ConnectionError::Io)
                } else {
                    connect_with_timeout(&b.address)
                        .await
                        .map_err(ConnectionError::Io)
                };

                match stream_result {
                    Ok(mut conn) => {
                        let server_name = b.name.clone();

                        let mode = self.effective_forwarding_mode(b.forwarding_override.clone());
                        let backend_type = b.backend_type.clone();
                        if let Err(e) = self
                            .send_backend_handshake(
                                &mut conn,
                                &fwd_host,
                                username,
                                uuid,
                                &props,
                                &mode,
                                &backend_type,
                            )
                            .await
                        {
                            tracing::warn!(
                                username = %username,
                                server   = %server_name,
                                err      = %e,
                                "backend handshake failed"
                            );
                            return self
                                .run_limbo_then_connect(username, session, &fwd_host, uuid)
                                .await;
                        }
                        match self.complete_backend_login(&mut conn).await {
                            Ok(backend_threshold) => {
                                b.player_count.fetch_add(1, Ordering::Relaxed);
                                session.write().await.current_server = Some(server_name.clone());
                                tracing::info!(
                                    username = %username,
                                    server   = %server_name,
                                    "connected to backend"
                                );
                                Ok((conn, backend_threshold))
                            },
                            Err(e) => {
                                tracing::warn!(
                                    username = %username,
                                    server   = %server_name,
                                    err      = %e,
                                    "backend login sequence failed — entering limbo"
                                );
                                self.run_limbo_then_connect(username, session, &fwd_host, uuid)
                                    .await
                            },
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            username = %username,
                            err      = %e,
                            "backend unreachable — entering limbo"
                        );
                        self.run_limbo_then_connect(username, session, &fwd_host, uuid)
                            .await
                    },
                }
            },
            None => {
                tracing::warn!(username = %username, "no backend configured — entering limbo");
                self.run_limbo_then_connect(username, session, &fwd_host, uuid)
                    .await
            },
        }
    }

    async fn run_limbo_then_connect(
        &mut self,
        username: &str,
        session: SharedSession,
        fwd_host: &str,
        uuid: Uuid,
    ) -> Result<(TcpStream, i32), ConnectionError> {
        let props = session.read().await.properties.clone();
        let mut limbo = crate::limbo::LimboHandler::new(
            &mut self.stream,
            Arc::clone(&self.state),
            session.clone(),
            self.protocol_version,
            self.compression_threshold,
            self.ml_session.kind,
        );
        let mut backend = limbo.run().await?;
        let selected_server = self.state.routing.select(&self.state.server_registry);
        let mode = self.effective_forwarding_mode(
            selected_server
                .as_ref()
                .and_then(|b| b.forwarding_override.clone()),
        );
        let backend_type = selected_server
            .as_ref()
            .map(|b| b.backend_type.clone())
            .unwrap_or_default();
        self.send_backend_handshake(
            &mut backend,
            fwd_host,
            username,
            uuid,
            &props,
            &mode,
            &backend_type,
        )
        .await?;
        let backend_threshold = self.complete_backend_login(&mut backend).await?;
        if let Some(b) = self.state.routing.select(&self.state.server_registry) {
            b.player_count.fetch_add(1, Ordering::Relaxed);
            session.write().await.current_server = Some(b.name.clone());
            tracing::info!(
                username = %username,
                server   = %b.name,
                "connected to backend after limbo"
            );
        }
        Ok((backend, backend_threshold))
    }

    fn effective_forwarding_mode(
        &self,
        per_server_override: Option<kojacoord_config::ForwardingMode>,
    ) -> kojacoord_config::ForwardingMode {
        if let Some(mode) = per_server_override {
            return mode;
        }
        let global = self.state.config.forwarding.mode.clone();
        if matches!(global, kojacoord_config::ForwardingMode::None)
            && self.state.config.proxy.ip_forward
        {
            kojacoord_config::ForwardingMode::Bungeecord
        } else {
            global
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_backend_handshake(
        &self,
        conn: &mut TcpStream,
        server_address: &str,
        username: &str,
        uuid: Uuid,
        properties: &[kojacoord_auth::ProfileProperty],
        mode: &kojacoord_config::ForwardingMode,
        backend_type: &kojacoord_config::BackendType,
    ) -> Result<(), ConnectionError> {
        let proto = self.protocol_version;

        let clean_host = server_address
            .split('\0')
            .next()
            .unwrap_or(server_address)
            .to_string();

        let is_forge_like = matches!(
            backend_type,
            kojacoord_config::BackendType::Forge | kojacoord_config::BackendType::Hybrid
        );

        let fml_marker = match self.ml_session.kind {
            modloader::ModloaderKind::Fml1 => "\0FML\0",
            modloader::ModloaderKind::Fml2 => "\0FML2\0",
            modloader::ModloaderKind::Fml3 => "\0FML3\0",
            _ => "",
        };

        let handshake_address = if matches!(mode, kojacoord_config::ForwardingMode::Bungeecord) {
            let profile = kojacoord_auth::AuthenticatedProfile {
                id: uuid,
                name: username.to_string(),
                properties: properties.to_vec(),
            };
            let suffix = bungeecord_suffix(&self.addr.ip(), &profile).map_err(|e| {
                ConnectionError::Auth(format!("Failed to create Bungeecord suffix: {}", e))
            })?;
            let base = format!("{}{}", clean_host, suffix);
            if is_forge_like {
                format!("{}{}", base, fml_marker)
            } else {
                base
            }
        } else {
            if is_forge_like {
                modloader::apply_fml_marker(&clean_host, self.ml_session.kind)
            } else {
                clean_host
            }
        };

        tracing::debug!(
            modloader = ?self.ml_session.kind,
            forwarding = ?mode,
            address_escaped = %handshake_address.replace('\0', "\\0"),
            address_len = handshake_address.len(),
            "sending backend handshake address"
        );

        {
            let hs_id = REGISTRY
                .get_id_for_version(
                    proto,
                    ProtocolState::Handshake,
                    Direction::Serverbound,
                    "ServerboundHandshake",
                )
                .unwrap_or(0x00);
            let pkt = ServerboundHandshake {
                protocol_version: VarInt(proto as i32),
                server_address: handshake_address,
                server_port: 25565,
                next_state: VarInt(2),
            };
            let mut payload = BytesMut::new();
            VarInt(hs_id as i32).encode(&mut payload)?;
            pkt.encode(&mut payload)?;
            crate::packet_io::write_packet(conn, &payload, NO_COMPRESSION).await?;
        }

        {
            let ls_id = sb_login(proto, "ServerboundLoginStart");
            let mut ls_payload = BytesMut::new();
            VarInt(ls_id as i32).encode(&mut ls_payload)?;
            let ver = nearest(proto);
            if matches!(
                ver,
                ProtocolVersion::V1_19_4 | ProtocolVersion::V1_20_4 | ProtocolVersion::V1_21
            ) {
                use kojacoord_protocol::versions::v1_20_4::login::ServerboundLoginStart;
                ServerboundLoginStart {
                    username: username.to_string(),
                    uuid,
                }
                .encode(&mut ls_payload)?;
            } else if matches!(ver, ProtocolVersion::V1_16_5) {
                use kojacoord_protocol::versions::v1_16_5::login::ServerboundLoginStart;
                ServerboundLoginStart {
                    username: username.to_string(),
                }
                .encode(&mut ls_payload)?;
            } else {
                use kojacoord_protocol::versions::v1_8::login::ServerboundLoginStart;
                ServerboundLoginStart {
                    username: username.to_string(),
                }
                .encode(&mut ls_payload)?;
            }
            crate::packet_io::write_packet(conn, &ls_payload, NO_COMPRESSION).await?;
        }

        Ok(())
    }

    async fn complete_backend_login(
        &mut self,
        conn: &mut TcpStream,
    ) -> Result<i32, ConnectionError> {
        let proto = self.protocol_version;
        let mut backend_threshold: i32 = NO_COMPRESSION;

        let id_set_compression = cb_login(proto, "ClientboundSetCompression");
        let id_login_success = cb_login(proto, "ClientboundLoginSuccess");
        let id_login_plugin = cb_login(proto, "ClientboundLoginPluginRequest");
        let id_login_plugin_sb = sb_login(proto, "ServerboundLoginPluginResponse");
        let id_login_ack = sb_login(proto, "ServerboundLoginAcknowledged");
        let id_cfg_ack = sb_config(proto, "AcknowledgeFinishConfiguration");
        let id_login_disconnect = cb_login(proto, "ClientboundLoginDisconnect");
        let id_encryption_request = cb_login(proto, "ClientboundEncryptionRequest");

        loop {
            let pkt_bytes = crate::packet_io::read_packet(conn, backend_threshold)
                .await
                .map_err(|e| {
                    tracing::warn!(err = %e, "EOF/IO error reading backend login packet");
                    e
                })?;

            let mut cursor = pkt_bytes.clone();
            let packet_id = VarInt::decode(&mut cursor)
                .map_err(ConnectionError::Protocol)?
                .0 as u8;

            tracing::trace!(packet_id, backend_threshold, "backend login packet");

            if packet_id == id_encryption_request {
                let ver = nearest(proto);
                if matches!(ver, ProtocolVersion::V1_7_10 | ProtocolVersion::V1_8) {
                    use kojacoord_protocol::versions::v1_16_5::login::ClientboundEncryptionRequest;
                    let pkt = ClientboundEncryptionRequest::decode(&mut cursor)
                        .map_err(ConnectionError::Protocol)?;

                    let mut new_payload = BytesMut::new();
                    VarInt(id_encryption_request as i32).encode(&mut new_payload)?;

                    if matches!(ver, ProtocolVersion::V1_7_10) {
                        use kojacoord_protocol::versions::v1_7_10::login::ClientboundEncryptionRequest as V1_7_Enc;
                        let client_pkt = V1_7_Enc {
                            server_id: pkt.server_id,
                            public_key: pkt.public_key,
                            verify_token: pkt.verify_token,
                        };
                        client_pkt.encode(&mut new_payload)?;
                    } else {
                        use kojacoord_protocol::versions::v1_8::login::ClientboundEncryptionRequest as V1_8_Enc;
                        let client_pkt = V1_8_Enc {
                            server_id: pkt.server_id,
                            public_key: pkt.public_key,
                            verify_token: pkt.verify_token,
                        };
                        client_pkt.encode(&mut new_payload)?;
                    }

                    crate::packet_io::write_packet(
                        &mut self.stream,
                        &new_payload,
                        self.compression_threshold,
                    )
                    .await?;
                    continue;
                }
            }

            if packet_id == id_set_compression {
                let threshold = VarInt::decode(&mut cursor)
                    .map_err(ConnectionError::Protocol)?
                    .0;
                backend_threshold = threshold;
                tracing::debug!(threshold, "backend enabled compression");
            } else if packet_id == id_login_success {
                tracing::debug!("backend sent LoginSuccess — login sequence complete");
                let ver = nearest(proto);
                match ver {
                    ProtocolVersion::V1_8 => {
                        use kojacoord_protocol::versions::v1_8::login::ClientboundLoginSuccess;
                        let _ = ClientboundLoginSuccess::decode(&mut cursor);
                    },
                    ProtocolVersion::V1_7_10 => {
                        use kojacoord_protocol::versions::v1_7_10::login::ClientboundLoginSuccess;
                        let _ = ClientboundLoginSuccess::decode(&mut cursor);
                    },
                    ProtocolVersion::V1_12_2 => {
                        use kojacoord_protocol::versions::v1_12_2::login::ClientboundLoginSuccess;
                        let _ = ClientboundLoginSuccess::decode(&mut cursor);
                    },
                    _ => {
                        use kojacoord_protocol::versions::v1_12_2::login::ClientboundLoginSuccess;
                        let _ = ClientboundLoginSuccess::decode(&mut cursor);
                    },
                }
                break;
            } else if packet_id == id_login_plugin {
                use kojacoord_protocol::versions::v1_20_4::login::ServerboundLoginPluginResponse;

                let message_id = VarInt::decode(&mut cursor).map_err(ConnectionError::Protocol)?;
                let channel = String::decode(&mut cursor).map_err(ConnectionError::Protocol)?;
                let remaining: Vec<u8> = cursor.to_vec();

                tracing::debug!(
                    message_id = message_id.0,
                    channel    = %channel,
                    "backend LoginPluginRequest"
                );

                if modloader::is_fml3_login_channel(&channel) {
                    modloader::log_fml3_login_packet(&channel, &remaining, "S→C", proto);

                    let mut req_payload = BytesMut::new();
                    VarInt(id_login_plugin as i32).encode(&mut req_payload)?;
                    message_id.encode(&mut req_payload)?;
                    channel.clone().encode(&mut req_payload)?;
                    req_payload.extend_from_slice(&remaining);
                    crate::packet_io::write_packet(
                        &mut self.stream,
                        &req_payload,
                        self.compression_threshold,
                    )
                    .await?;

                    let client_raw =
                        crate::packet_io::read_packet(&mut self.stream, self.compression_threshold)
                            .await?;

                    let mut client_cursor = client_raw.clone();
                    let client_pkt_id = VarInt::decode(&mut client_cursor)
                        .map_err(ConnectionError::Protocol)?
                        .0 as u8;

                    if client_pkt_id == id_login_plugin_sb {
                        crate::packet_io::write_packet(conn, &client_raw, backend_threshold)
                            .await?;
                        tracing::debug!(
                            message_id = message_id.0,
                            channel    = %channel,
                            "FML3 LoginPluginResponse relayed"
                        );
                    } else {
                        tracing::warn!(
                            client_pkt_id,
                            channel = %channel,
                            "unexpected client packet during FML3 — sending empty response"
                        );
                        let pkt = ServerboundLoginPluginResponse {
                            message_id,
                            data: vec![].into(),
                        };
                        let mut resp = BytesMut::new();
                        VarInt(id_login_plugin_sb as i32).encode(&mut resp)?;
                        pkt.encode(&mut resp)?;
                        crate::packet_io::write_packet(conn, &resp, backend_threshold).await?;
                    }
                } else {
                    let pkt = ServerboundLoginPluginResponse {
                        message_id,
                        data: vec![].into(),
                    };
                    let mut resp = BytesMut::new();
                    VarInt(id_login_plugin_sb as i32).encode(&mut resp)?;
                    pkt.encode(&mut resp)?;
                    crate::packet_io::write_packet(conn, &resp, backend_threshold).await?;
                    tracing::debug!(channel = %channel, "empty LoginPluginResponse (non-FML)");
                }
            } else if packet_id == id_login_disconnect {
                let reason = String::decode(&mut cursor).unwrap_or_else(|_| "<unreadable>".into());
                tracing::warn!(
                    reason = %reason,
                    "backend sent LoginDisconnect"
                );
                return Err(ConnectionError::Closed);
            } else {
                tracing::warn!(
                    packet_id,
                    set_compression = id_set_compression,
                    login_success = id_login_success,
                    login_plugin = id_login_plugin,
                    login_disconnect = id_login_disconnect,
                    "unexpected backend login packet — skipping"
                );
            }
        }

        let ver = nearest(proto);
        if matches!(
            ver,
            ProtocolVersion::V1_19_4 | ProtocolVersion::V1_20_4 | ProtocolVersion::V1_21
        ) {
            {
                let actual =
                    crate::packet_io::read_packet(&mut self.stream, self.compression_threshold)
                        .await?;
                let mut cursor = actual;
                let pkt_id = VarInt::decode(&mut cursor)
                    .map_err(ConnectionError::Protocol)?
                    .0 as u8;
                let expected = sb_login(proto, "ServerboundLoginAcknowledged");
                if pkt_id != expected {
                    tracing::warn!(
                        pkt_id,
                        expected,
                        "expected LoginAcknowledged from client, got something else"
                    );
                } else {
                    tracing::debug!(packet_id = pkt_id, "received LoginAcknowledged from client");
                }
            }

            {
                use kojacoord_protocol::versions::v1_20_4::login::ServerboundLoginAcknowledged;
                let pkt = ServerboundLoginAcknowledged {};
                let mut ack = BytesMut::new();
                VarInt(id_login_ack as i32).encode(&mut ack)?;
                pkt.encode(&mut ack)?;
                crate::packet_io::write_packet(conn, &ack, backend_threshold).await?;
                tracing::debug!(
                    packet_id = id_login_ack,
                    "sent LoginAcknowledged to backend"
                );
            }

            self.relay_config_phase(conn, backend_threshold).await?;

            {
                use kojacoord_protocol::versions::v1_20_4::config::ServerboundAcknowledgeFinishConfiguration;
                let pkt = ServerboundAcknowledgeFinishConfiguration {};
                let mut cfg_ack_buf = BytesMut::new();
                VarInt(id_cfg_ack as i32).encode(&mut cfg_ack_buf)?;
                pkt.encode(&mut cfg_ack_buf)?;
                crate::packet_io::write_packet(conn, &cfg_ack_buf, backend_threshold).await?;
                tracing::debug!(
                    packet_id = id_cfg_ack,
                    "sent AcknowledgeFinishConfiguration to backend"
                );
            }
        }

        Ok(backend_threshold)
    }

    async fn relay_config_phase(
        &mut self,
        backend: &mut TcpStream,
        backend_threshold: i32,
    ) -> Result<(), ConnectionError> {
        let proto = self.protocol_version;
        let client_thresh = self.compression_threshold;

        let id_finish_cfg = cb_config(proto, "FinishConfiguration");
        let id_cb_custom = cb_config(proto, "ClientboundCustomPayload");
        let id_sb_custom = sb_config(proto, "ServerboundCustomPayload");
        let id_cb_ping = cb_config(proto, "ClientboundPing");
        let id_cfg_ack_sb = sb_config(proto, "AcknowledgeFinishConfiguration");

        let mut buffered_for_client: Vec<Bytes> = Vec::new();

        loop {
            let raw_payload = crate::packet_io::read_packet(backend, backend_threshold).await?;

            let mut cursor = raw_payload.clone();
            let pkt_id = VarInt::decode(&mut cursor)
                .map_err(ConnectionError::Protocol)?
                .0 as u8;

            if pkt_id == id_finish_cfg {
                tracing::debug!("backend sent FinishConfiguration");
                break;
            }

            if pkt_id == id_cb_custom {
                let channel = String::decode(&mut cursor).unwrap_or_default();
                let chan_data = cursor.to_vec();

                if modloader::is_neo_config_channel(&channel) {
                    modloader::log_neo_config_packet(&channel, &chan_data, "S→C", proto);

                    if self.ml_session.kind == modloader::ModloaderKind::Unknown {
                        self.ml_session.kind = if channel.starts_with("neoforge:") {
                            tracing::debug!("detected NeoForge from config-phase channel");
                            modloader::ModloaderKind::NeoForge
                        } else if channel.starts_with("fabric") || channel.starts_with("c:") {
                            tracing::debug!("detected Fabric from config-phase channel");
                            modloader::ModloaderKind::Fabric
                        } else {
                            self.ml_session.kind
                        };
                    }

                    crate::packet_io::write_packet(&mut self.stream, &raw_payload, client_thresh)
                        .await?;

                    let resp_raw =
                        crate::packet_io::read_packet(&mut self.stream, client_thresh).await?;

                    let mut rcursor = resp_raw.clone();
                    let resp_pkt_id = VarInt::decode(&mut rcursor)
                        .map_err(ConnectionError::Protocol)?
                        .0 as u8;
                    if resp_pkt_id == id_sb_custom {
                        let resp_chan = String::decode(&mut rcursor).unwrap_or_default();
                        modloader::log_neo_config_packet(
                            &resp_chan,
                            rcursor.as_ref(),
                            "C→S",
                            proto,
                        );
                    }
                    crate::packet_io::write_packet(backend, &resp_raw, backend_threshold).await?;
                } else {
                    buffered_for_client.push(raw_payload);
                }
            } else if pkt_id == id_cb_ping {
                tracing::debug!("relaying config-phase Ping");
                crate::packet_io::write_packet(&mut self.stream, &raw_payload, client_thresh)
                    .await?;

                let pong_raw =
                    crate::packet_io::read_packet(&mut self.stream, client_thresh).await?;
                crate::packet_io::write_packet(backend, &pong_raw, backend_threshold).await?;
                tracing::debug!("config-phase Ping/Pong relayed");
            } else {
                buffered_for_client.push(raw_payload);
            }
        }

        for pkt in buffered_for_client {
            crate::packet_io::write_packet(&mut self.stream, &pkt, client_thresh).await?;
        }

        {
            use kojacoord_protocol::versions::v1_20_4::config::ClientboundFinishConfiguration;
            let finish_cb_id = cb_config(proto, "FinishConfiguration");
            let pkt = ClientboundFinishConfiguration {};
            let mut p = BytesMut::new();
            VarInt(finish_cb_id as i32).encode(&mut p)?;
            pkt.encode(&mut p)?;
            crate::packet_io::write_packet(&mut self.stream, &p, client_thresh).await?;
            tracing::debug!("sent FinishConfiguration to client");
        }

        loop {
            let resp_raw = crate::packet_io::read_packet(&mut self.stream, client_thresh).await?;
            let mut rcursor = resp_raw.clone();
            let rpkt = VarInt::decode(&mut rcursor)
                .map_err(ConnectionError::Protocol)?
                .0 as u8;
            if rpkt == id_cfg_ack_sb {
                tracing::debug!("received AcknowledgeFinishConfiguration from client");
                break;
            }
            tracing::debug!(rpkt, "ignoring client config packet while waiting for Ack");
        }

        self.ml_session.handshake_complete = true;
        Ok(())
    }

    async fn relay(
        &mut self,
        backend: TcpStream,
        session: SharedSession,
        backend_compression_threshold: i32,
    ) -> Result<crate::relay::RelayExit, ConnectionError> {
        let current_server = session.read().await.current_server.clone();
        let lobby_name = &self.state.config.proxy.lobby_server_name;

        let is_lobby = current_server
            .as_deref()
            .map(|name| name == lobby_name.as_str())
            .unwrap_or(false);

        let backend_protocol = if is_lobby {
            self.state.config.proxy.lobby_server_protocol
        } else {
            let server_protocol = self
                .state
                .config
                .servers
                .iter()
                .find(|s| s.name == current_server.as_deref().unwrap_or(""))
                .and_then(|s| {
                    if s.backend_protocol > 0 {
                        Some(s.backend_protocol)
                    } else {
                        None
                    }
                });

            if self.protocol_version == 5 || self.protocol_version == 47 {
                server_protocol.unwrap_or(340)
            } else {
                server_protocol.unwrap_or(self.protocol_version)
            }
        };

        let conversion_enabled = (is_lobby && backend_protocol != self.protocol_version)
            || self.protocol_version == 5
            || self.protocol_version == 47;

        if conversion_enabled {
            tracing::debug!(
                client_proto  = self.protocol_version,
                backend_proto = backend_protocol,
                server        = %current_server.as_deref().unwrap_or("?"),
                "protocol conversion enabled"
            );
        }

        PacketRelay {
            client_stream: std::mem::replace(&mut self.stream, McStream::Empty),
            backend_stream: backend,
            session: session.clone(),
            state: Arc::clone(&self.state),
            protocol_version: self.protocol_version,
            client_compression_threshold: self.compression_threshold,
            backend_compression_threshold,
            ml_kind: self.ml_session.kind,
            conversion_enabled: is_lobby,
            backend_protocol,
        }
        .run()
        .await
    }

    async fn write_login_packet<P: Encode>(
        &mut self,
        packet: P,
        pid: u8,
    ) -> Result<(), ConnectionError> {
        let mut payload = BytesMut::new();
        VarInt(pid as i32).encode(&mut payload)?;
        packet.encode(&mut payload)?;
        crate::packet_io::write_packet(&mut self.stream, &payload, self.compression_threshold)
            .await?;
        Ok(())
    }
}
