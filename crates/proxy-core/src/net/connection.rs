//! Per-client connection state machine.
//!
//! [`ClientConnection`] is the lifecycle of one TCP socket from accept
//! to disconnect — sniffs the PROXY-protocol header (if enabled),
//! reads the Minecraft handshake, dispatches to status/login/limbo as
//! appropriate, runs the Mojang auth dance, opens the backend, and
//! finally hands the socket off to `PacketRelay` for the play phase.
//!
//! [`McStream`] is the half-duplex abstraction that lets the rest of
//! the module write to a TCP stream that may or may not be wrapped in
//! AES-CFB8 encryption — the cipher kicks in mid-handshake, so we
//! need a single type that can switch from `Plain` to `Encrypted`
//! without changing the calling code.
//!
//! The rest of the file is a big pile of per-version helpers
//! (`send_login_success`, `send_encryption_request`, …) that
//! construct typed packets and route them through
//! [`Self::write_typed`], which resolves the packet id at compile
//! time via the `PacketId` trait — no registry lookup on the hot
//! path.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use uuid::Uuid;

use aes::cipher::BlockEncrypt;
use aes::Aes128;
use bytes::{BufMut, Bytes, BytesMut};
use kojacoord_protocol::{CanonicalVersion, Epoch, MinecraftEdition, ProtocolVersion};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use kojacoord_protocol::{
    codec::{Decode, Encode, PacketId},
    types::VarInt,
    versions::v1_6_x::status::ClientboundLegacyMotd,
    versions::v1_8_x::{
        handshake::ServerboundHandshake,
        status::{ClientboundPongResponse, ClientboundStatusResponse, ServerboundPingRequest},
    },
};

use crate::{
    error::ConnectionError,
    modloader,
    packet_builder::build_system_message_packet,
    packet_ids::{cb_config, cb_login, nearest, sb_config, sb_login},
    packet_io::{read_varint, NO_COMPRESSION},
    proxy::ProxyState,
    relay::PacketRelay,
    session::{ConnectionState, PlayerSession, SharedSession},
};

use kojacoord_auth::{
    forwarding::{bungeecord_suffix, velocity_header},
    AuthEvent, AuthOutbound,
};

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

/// Underlying socket; either plain TCP or AES-CFB8 encrypted after the
/// Login exchange. `Empty` is a tombstone used during the
/// hand-over to `PacketRelay` when the original stream is moved out.
#[allow(clippy::large_enum_variant)]
pub enum McStreamKind {
    Empty,
    Plain(TcpStream),
    Encrypted(EncryptedStream),
}

/// Wrapper around [`McStreamKind`] with a one-shot byte-prefix
/// buffer. The buffer exists for a single reason: the legacy-ping
/// sniffer in [`ClientConnection::run`] needs to peek the first byte
/// to detect 0xFE without consuming bytes the modern handshake parser
/// will need. After reading the peek byte, if it's not 0xFE we push
/// it back into `prefix`; the next `poll_read` drains it before
/// delegating to the inner stream.
pub struct McStream {
    kind: McStreamKind,
    prefix: std::collections::VecDeque<u8>,
}

impl McStream {
    pub fn plain(stream: TcpStream) -> Self {
        Self {
            kind: McStreamKind::Plain(stream),
            prefix: std::collections::VecDeque::new(),
        }
    }

    pub fn empty() -> Self {
        Self {
            kind: McStreamKind::Empty,
            prefix: std::collections::VecDeque::new(),
        }
    }

    /// Push bytes to the head of the read queue. The next read will
    /// drain these before touching the underlying socket. Used by the
    /// legacy-ping detector to put the peeked byte back when the
    /// connection turns out to be a modern handshake.
    pub fn push_prefix(&mut self, bytes: &[u8]) {
        self.prefix.extend(bytes.iter().copied());
    }

    /// Upgrade a Plain connection to Encrypted using the negotiated
    /// AES-CFB8 session key. Any pending `prefix` bytes carry across
    /// — they were already plaintext when we read them.
    pub fn enable_encryption(&mut self, key: &[u8]) {
        let old = std::mem::replace(&mut self.kind, McStreamKind::Empty);
        self.kind = match old {
            McStreamKind::Plain(stream) => {
                McStreamKind::Encrypted(EncryptedStream::new(stream, key))
            },
            McStreamKind::Encrypted(stream) => McStreamKind::Encrypted(stream),
            McStreamKind::Empty => unreachable!("enable_encryption on Empty stream"),
        };
    }
}

impl AsyncRead for McStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Drain prefix first. Once it's empty, fall through to the
        // underlying stream so the same `poll_read` call returns
        // some prefix + some socket bytes when the caller asks for
        // more than the prefix has.
        if !this.prefix.is_empty() {
            let n = std::cmp::min(this.prefix.len(), buf.remaining());
            for _ in 0..n {
                if let Some(b) = this.prefix.pop_front() {
                    buf.put_slice(&[b]);
                }
            }
            return Poll::Ready(Ok(()));
        }
        match &mut this.kind {
            McStreamKind::Empty => Poll::Ready(Ok(())),
            McStreamKind::Plain(s) => Pin::new(s).poll_read(cx, buf),
            McStreamKind::Encrypted(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for McStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.get_mut().kind {
            McStreamKind::Empty => Poll::Ready(Ok(buf.len())),
            McStreamKind::Plain(s) => Pin::new(s).poll_write(cx, buf),
            McStreamKind::Encrypted(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().kind {
            McStreamKind::Empty => Poll::Ready(Ok(())),
            McStreamKind::Plain(s) => Pin::new(s).poll_flush(cx),
            McStreamKind::Encrypted(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().kind {
            McStreamKind::Empty => Poll::Ready(Ok(())),
            McStreamKind::Plain(s) => Pin::new(s).poll_shutdown(cx),
            McStreamKind::Encrypted(s) => Pin::new(s).poll_shutdown(cx),
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
            stream: McStream::plain(stream),
            addr,
            state,
            conn_state: ConnectionState::Handshaking,
            protocol_version: 0,
            compression_threshold: NO_COMPRESSION,
            ml_session: modloader::ModloaderSession::new(),
        }
    }

    /// Top-level entry: drive the connection through handshake →
    /// status/login → play, and **always** kick the client gracefully
    /// before returning when something fails mid-way. Without this
    /// wrapper, an early `?` would drop the TCP socket with no
    /// disconnect packet — modern clients show "Connection reset"
    /// instead of the actual reason.
    pub async fn run(mut self) -> Result<(), ConnectionError> {
        let result = self.run_inner().await;
        if let Err(ref e) = result {
            self.send_graceful_kick(e).await;
        }
        result
    }

    /// Send a state-appropriate Disconnect packet describing `err` to
    /// the client, then return. Errors during the kick itself are
    /// swallowed — we're already on the way out.
    ///
    /// Behaviour depends on the current `conn_state`:
    ///   * `Login` / `Configuration` → LoginDisconnect (login state).
    ///   * `Play`                    → play-state Disconnect.
    ///   * `Status` / `Handshaking`  → silent; the wire spec has no
    ///     disconnect packet for these.
    ///
    /// Errors that mean "the client already left" (`ConnectionError::Closed`,
    /// any `Io` error) are also silent — there's nobody to talk to.
    async fn send_graceful_kick(&mut self, err: &ConnectionError) {
        if matches!(err, ConnectionError::Closed | ConnectionError::Io(_)) {
            return;
        }
        let reason = match err {
            ConnectionError::Auth(msg) => msg.clone(),
            other => other.to_string(),
        };
        // Modern clients want a chat-component JSON; pre-netty wants a
        // raw string. `send_disconnect_login` / `send_play_disconnect`
        // both branch on `is_pre_netty_proto` and emit the right shape.
        let json = serde_json::json!({
            "text": format!("Disconnected: {}", reason),
            "color": "red",
        })
        .to_string();
        match self.conn_state {
            ConnectionState::Login | ConnectionState::Configuration => {
                let _ = self.send_disconnect_login(&json).await;
            },
            ConnectionState::Play => {
                let _ = self.send_play_disconnect(&json).await;
            },
            ConnectionState::Status | ConnectionState::Handshaking => {
                // No disconnect packet exists in these states.
            },
        }
    }

    async fn run_inner(&mut self) -> Result<(), ConnectionError> {
        if self.state.config.proxy.proxy_protocol {
            if self.state.config.proxy.proxy_protocol_optional {
                // Optional mode: try to parse PROXY header, fall back to direct connection
                match crate::net::proxy_protocol::read_proxy_header_optional(&mut self.stream).await
                {
                    Ok(crate::net::proxy_protocol::ProxyHeaderResult::Found(real_addr)) => {
                        tracing::debug!(original = %self.addr, real = %real_addr, "parsed PROXY protocol header");
                        self.addr = real_addr;
                    },
                    Ok(crate::net::proxy_protocol::ProxyHeaderResult::NotFound(_bytes)) => {
                        tracing::debug!("No PROXY header detected, using direct connection");
                        // Bytes are consumed but would need to be handled for the handshake
                        // For now, we'll proceed with the direct address
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse PROXY protocol header");
                        return Err(e);
                    },
                }
            } else {
                // Strict mode: PROXY header is required
                match crate::net::proxy_protocol::read_proxy_header(&mut self.stream, self.addr)
                    .await
                {
                    Ok(real_addr) => {
                        tracing::debug!(original = %self.addr, real = %real_addr, "parsed proxy protocol header");
                        self.addr = real_addr;
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse proxy protocol header");
                        return Err(e);
                    },
                }
            }
        }

        // Metrics bookkeeping (connection / disconnection / failed)
        // is owned by `proxy::accept_loop` — single accounting
        // layer, no double counting on either the happy path or
        // any of the early-return error paths below.

        // Legacy 0xFE-ping detection.
        //
        // Pre-1.7 clients send a single raw 0xFE byte (the
        // pre-netty server-list-ping packet) before any handshake.
        // Modern clients start with a varint-length-prefixed
        // handshake whose first byte is the *length*, never 0xFE
        // for any reasonable handshake (lengths fit in one byte, so
        // the byte equals the length — typically 15–30).
        //
        // We peek a single raw byte. If it's 0xFE, dispatch to the
        // legacy handler (which expects to read more 0xFE-style
        // payload itself). Otherwise push the byte back into the
        // stream's prefix buffer so the modern handshake parser
        // sees the full length-prefixed frame.
        let mut peek = [0u8; 1];
        let peek_result = tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_exact(&mut self.stream, &mut peek),
        )
        .await;
        match peek_result {
            Ok(Ok(_)) => {},
            Ok(Err(_)) | Err(_) => {
                return Err(ConnectionError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection timed out",
                )));
            },
        }

        if peek[0] == 0xFE {
            tracing::debug!("detected legacy 0xFE ping from pre-1.7 client");
            return self.handle_legacy_ping().await;
        }

        // Bedrock Edition detection.
        //
        // Bedrock uses RakNet over UDP, NOT TCP — so in steady state a
        // Bedrock client never lands here. But people DO occasionally
        // misconfigure their client to point a Bedrock address at the
        // proxy's TCP port, and some "universal launcher" wrappers
        // attempt a TCP probe before falling back to UDP. We sniff for
        // RakNet's `ID_OPEN_CONNECTION_REQUEST_1 = 0x05` followed by
        // the well-known 16-byte "Offline Message Data ID" magic
        // `00 ff ff 00 fe fe fe fe fd fd fd fd 12 34 56 78`. If we
        // see that, we know it's Bedrock and can disconnect cleanly
        // with a message instead of letting the modern parser misread
        // those bytes as a Java handshake frame.
        //
        // `MinecraftEdition::Bedrock.is_implemented()` returns `false`
        // today; once the dedicated Bedrock pipeline lands, this
        // branch will dispatch into it instead of kicking.
        if peek[0] == 0x05 && self.peek_looks_like_bedrock().await {
            return self.handle_bedrock_unsupported().await;
        }

        // Pre-netty (1.6.x) login detection.
        //
        // 1.6.x clients send packet 0x02 (Handshake/Login Start) as the
        // very first thing on a join — single raw `0x02` byte followed by
        // `protocol_version(u8), username(UCS-2 short-prefix),
        // host(UCS-2 short-prefix), port(i32)`. A modern handshake CANNOT
        // have a length-varint of 2 (the smallest valid modern handshake
        // frame is ~10 bytes — packet id + protocol VarInt + 1-byte addr
        // length + addr + u16 port + next-state VarInt), so a peek byte
        // of `0x02` is unambiguously a 1.6.x join attempt.
        //
        // Without this branch, the modern parser at the bottom of this
        // function would interpret `0x02` as a frame-length of 2, read
        // two bytes of legacy payload, then try to VarInt-decode those
        // garbage bytes as a packet id — failure looks like a confusing
        // protocol error rather than the obvious "wrong epoch" it is.
        if peek[0] == 0x02 {
            tracing::debug!("detected legacy 0x02 handshake from pre-1.7 client");
            return self.handle_legacy_login().await;
        }

        // Push the peeked byte back so the modern handshake parser
        // reads it as part of the length varint.
        self.stream.push_prefix(&peek);

        let handshake = match tokio::time::timeout(
            tokio::time::Duration::from_secs(10),
            self.read_packet::<ServerboundHandshake>(),
        )
        .await
        {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(ConnectionError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "handshake timed out",
                )));
            },
        };

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

        // accept_loop calls record_disconnection / record_failed_connection
        // based on this return value — don't double-count here.
        result
    }

    async fn read_packet<T: Decode + PacketId>(&mut self) -> Result<T, ConnectionError> {
        let mut bytes =
            crate::packet_io::read_packet(&mut self.stream, self.compression_threshold).await?;
        let _ = VarInt::decode(&mut bytes)?;
        // Per-player metrics are recorded in the relay loop where a UUID is
        // already known — during the handshake/login phase the connection
        // isn't yet associated with a player.
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

        let cached = self.state.cached_status.load();

        // Fire ServerListPing event to allow plugins to customize the player sample
        let online_players = self.state.sessions.len();
        let max_players = self.state.config.proxy.max_players;

        use kojacoord_plugin_system::api::PluginEvent;
        let plugin_responses = self
            .state
            .plugin_manager
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .broadcast_event(&PluginEvent::ServerListPing {
                max_players,
                online_players,
                sample: Vec::new(),
            });

        // Check if any plugin customized the player sample
        let custom_sample = plugin_responses.iter().find_map(|r| {
            if let kojacoord_plugin_system::api::PluginResponse::UpdatePlayerSample { sample } = r {
                Some(sample.clone())
            } else {
                None
            }
        });

        // Build the JSON response with custom sample if provided
        let json = if let Some(sample) = custom_sample {
            let sample_json = sample
                .iter()
                .map(|p| format!(r#"{{"name":"{}","uuid":"{}"}}"#, p.name, p.uuid))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                r#"{{"version":{{"name":"Koja","protocol":"{}"}},"players":{{"max":{},"online":{},"sample":[{}]}}{}}}"#,
                self.protocol_version, max_players, online_players, sample_json, cached.suffix
            )
        } else {
            [
                r#"{"version":{"name":"Koja","protocol":"#,
                &self.protocol_version.to_string(),
                &cached.suffix,
            ]
            .join("")
        };

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

    /// Handle a legacy (pre-netty / 1.6.x) join attempt.
    ///
    /// Mojang's pre-1.7 session.minecraft.net auth endpoint has been
    /// dead since 2014 — online-mode auth is impossible for 1.6.4 in
    /// practice, so the proxy forces offline-mode for these clients
    /// and skips the encryption dance entirely. Flow:
    ///   1. Parse the legacy Handshake packet 0x02
    ///      (protocol_version u8, username/host UCS-2 short-prefix,
    ///      port i32) per minecraft.wiki / Spigot 1.6.4 sources.
    ///   2. Generate the canonical "OfflinePlayer:<name>" v3 UUID.
    ///   3. Hand off to `finalise_login`, which sends the 1.6.4
    ///      LoginRequest (0x01) — `send_login_success` already
    ///      dispatches on V1_6_4 to use pre-netty framing — then
    ///      routes the connection into the relay/limbo loop.
    ///
    /// On any decode failure or pipeline error we fall back to a
    /// legacy 0xFF disconnect packet so the user sees a real message
    /// instead of a TCP reset.
    async fn handle_legacy_login(&mut self) -> Result<(), ConnectionError> {
        use kojacoord_protocol::codec::Decode;
        use kojacoord_protocol::versions::v1_6_x::login::{
            ClientboundLoginDisconnect, HandshakeC2S,
        };
        use tokio::io::AsyncReadExt;

        // Read everything the client has buffered. 1.6.4 handshakes are
        // small (≈40–80 bytes), so a single bounded read is fine.
        let mut buf = vec![0u8; 1024];
        let n = match tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            self.stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(ConnectionError::Io(e)),
            Err(_) => {
                return Err(ConnectionError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "legacy handshake timed out",
                )))
            },
        };
        buf.truncate(n);

        // The leading 0x02 packet-id byte was already consumed by the
        // accept-loop peek, so the buffer starts at the body.
        let mut body = bytes::Bytes::from(buf);
        let handshake = match HandshakeC2S::decode(&mut body) {
            Ok(hs) => {
                self.protocol_version = hs.protocol_version as u32;
                self.conn_state = ConnectionState::Login;
                tracing::info!(
                    username = %hs.username,
                    host = %hs.host,
                    port = hs.port,
                    protocol = hs.protocol_version,
                    "pre-netty (1.6.x) login attempt — offline mode (session.minecraft.net pre-1.7 endpoint is unreachable)"
                );
                hs
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to decode pre-netty handshake; closing");
                return Ok(());
            },
        };

        // 1.6.x identity resolution. Mojang killed session.minecraft.net
        // in 2014 so we can't run a real Yggdrasil session — but we can
        // still ask `api.mojang.com/users/profiles/minecraft/<name>` for
        // the player's REAL UUID. That UUID is what `cached_profiles`
        // is keyed on (written when the same player joined on 1.7+) so
        // using it here lights up the skin / properties recovery path.
        //
        // Policy:
        //   * Mojang lookup succeeds      → use the real UUID.
        //   * Mojang says "no such user"  → no paid account exists.
        //     In `online_mode = true`     → reject (anyone could claim
        //                                   the name otherwise).
        //     In `online_mode = false`    → fall back to the offline
        //                                   NAMESPACE_OID UUID.
        //   * Network failure             → fall back to offline UUID
        //                                   regardless of online_mode
        //                                   (a flaky network must not
        //                                   lock everyone out).
        let online_mode = self.state.config.proxy.online_mode;
        let resolved_uuid: Uuid = match kojacoord_auth::resolve_mojang_uuid(&handshake.username)
            .await
        {
            Ok(uuid) => {
                tracing::info!(
                    username = %handshake.username,
                    uuid = %uuid,
                    "Resolved 1.6.x username to real Mojang UUID"
                );
                uuid
            },
            Err(kojacoord_auth::MojangLookupError::NotFound(_)) if online_mode => {
                tracing::warn!(
                    username = %handshake.username,
                    "1.6.x login rejected — no Mojang account exists for this username and online_mode is on"
                );
                let reason_json = r#"{"text":"This server requires a Minecraft.net account. The username you joined with isn't registered.","color":"red"}"#;
                let plaintext = crate::packet_builder::plaintext_from_chat_json(reason_json);
                let pkt = ClientboundLoginDisconnect { reason: plaintext };
                let mut body = BytesMut::new();
                pkt.encode(&mut body).map_err(ConnectionError::Protocol)?;
                let mut frame = BytesMut::new();
                frame.put_u8(0xFF);
                frame.extend_from_slice(&body);
                use tokio::io::AsyncWriteExt;
                let _ = self.stream.write_all(&frame).await;
                let _ = self.stream.flush().await;
                return Ok(());
            },
            Err(e) => {
                tracing::warn!(
                    username = %handshake.username,
                    error = %e,
                    "Mojang UUID lookup failed; falling back to offline NAMESPACE_OID UUID"
                );
                // Canonical offline-player UUID per the Notchian server:
                // version-3 (MD5-namespaced) UUID over the ASCII bytes
                // of "OfflinePlayer:<username>". Same algorithm
                // Bukkit/Spigot use in `OfflinePlayer.getUniqueId`.
                Uuid::new_v3(
                    &Uuid::NAMESPACE_OID,
                    format!("OfflinePlayer:{}", handshake.username).as_bytes(),
                )
            },
        };

        fn client_gone(e: &ConnectionError) -> bool {
            matches!(e, ConnectionError::Closed | ConnectionError::Io(_))
        }

        match self
            .finalise_login(
                resolved_uuid,
                handshake.username.clone(),
                Vec::new(),
                handshake.host,
                &client_gone,
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(e) => {
                tracing::warn!(error = %e, "1.6.4 finalise_login failed; sending legacy kick");
            },
        }

        // Kick with a real 1.6.x disconnect packet: `0xFF` followed by a
        // UCS-2 short-prefixed reason. crate::packet_builder converts the
        // chat-component JSON to plaintext since 1.6.x has no JSON chat.
        let reason_json = r#"{"text":"1.6.4 login is not yet supported by this proxy. Use 1.7+ to connect.","color":"red"}"#;
        let plaintext = crate::packet_builder::plaintext_from_chat_json(reason_json);
        let pkt = ClientboundLoginDisconnect { reason: plaintext };
        let mut wire = bytes::BytesMut::new();
        use bytes::BufMut;
        wire.put_u8(0xFF);
        use kojacoord_protocol::codec::Encode;
        pkt.encode(&mut wire)?;
        crate::packet_io::write_legacy_bytes(&mut self.stream, &wire).await?;
        tracing::debug!("sent legacy disconnect to 1.6.x client");
        Ok(())
    }

    /// Handle legacy 0xFE ping from pre-1.7/1.6.x clients.
    /// These clients use a completely different protocol without varint framing.
    /// Read the next 16 bytes from the stream and check whether they
    /// match RakNet's Offline Message Data ID magic. Called only after
    /// the lead byte already matched `0x05`
    /// (`ID_OPEN_CONNECTION_REQUEST_1`). Magic value per the RakNet
    /// reference impl + minecraft.wiki Bedrock_Edition_protocol §RakNet.
    async fn peek_looks_like_bedrock(&mut self) -> bool {
        const RAKNET_MAGIC: [u8; 16] = [
            0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34,
            0x56, 0x78,
        ];
        let mut probe = [0u8; 16];
        let read_result = tokio::time::timeout(
            tokio::time::Duration::from_millis(200),
            tokio::io::AsyncReadExt::read_exact(&mut self.stream, &mut probe),
        )
        .await;
        match read_result {
            Ok(Ok(_)) => probe == RAKNET_MAGIC,
            _ => false,
        }
    }

    /// Kick a Bedrock client with a clear "not yet supported" message.
    /// Writes a tiny Bedrock-shaped `ID_INCOMPATIBLE_PROTOCOL_VERSION`
    /// (0x19) reply followed by closing the socket — that's the
    /// closest thing to a graceful kick that RakNet defines. Once
    /// `MinecraftEdition::Bedrock.is_implemented()` returns true the
    /// caller will dispatch into the real pipeline instead.
    async fn handle_bedrock_unsupported(&mut self) -> Result<(), ConnectionError> {
        use tokio::io::AsyncWriteExt;
        let edition = MinecraftEdition::Bedrock;
        tracing::info!(
            edition = edition.slug(),
            implemented = edition.is_implemented(),
            "rejected Bedrock connection — pipeline not yet implemented"
        );
        // RakNet `ID_INCOMPATIBLE_PROTOCOL_VERSION`: 0x19, then u8
        // (server's RakNet proto), then the 16-byte magic, then a i64
        // server GUID. Bedrock clients show "Unable to connect to
        // world" rather than a textual reason — that's the best the
        // protocol gives us without a real RakNet stack.
        let mut reply = BytesMut::new();
        reply.put_u8(0x19);
        reply.put_u8(0); // we don't actually speak any RakNet proto
        reply.put_slice(&[
            0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34,
            0x56, 0x78,
        ]);
        reply.put_i64(0); // synthetic server GUID
        let _ = self.stream.write_all(&reply).await;
        let _ = self.stream.flush().await;
        Err(ConnectionError::Closed)
    }

    async fn handle_legacy_ping(&mut self) -> Result<(), ConnectionError> {
        // Drain the extended SLP payload that 1.4+ / 1.6 clients tack
        // onto the bare `0xFE` ping byte. Per minecraft.wiki Server
        // List Ping:
        //   * pre-1.4: bare 0xFE only
        //   * 1.4 - 1.5: 0xFE 0x01
        //   * 1.6: 0xFE 0x01 0xFA [u16-be channel len] "MC|PingHost"
        //          [u16-be payload len] [u8 proto] [u16-be host len UCS-2]
        //          [host bytes] [i32 port]
        //
        // We MUST drain ALL pending request bytes before writing the
        // response and closing. If unread bytes are sitting in the
        // receive buffer when we close, the OS (especially Windows)
        // sends a TCP RST instead of FIN — the client then sees
        // "Connection error" rather than the MOTD we already wrote.
        //
        // Strategy: read in a loop with a 250ms-per-chunk timeout
        // until either (a) we hit EOF, (b) the chunk timeout fires
        // (client is done sending), or (c) we've drained over the
        // upper bound a 1.6 extended request can legally produce
        // (~512 bytes is generous; a typical request is ~36 bytes
        // plus the hostname).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut throwaway = [0u8; 256];
        let mut drained_total = 0usize;
        loop {
            match tokio::time::timeout(
                tokio::time::Duration::from_millis(250),
                self.stream.read(&mut throwaway),
            )
            .await
            {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => {
                    drained_total += n;
                    if drained_total >= 1024 {
                        break; // upper-bound safety
                    }
                },
                Ok(Err(_)) => break, // socket error — treat as drained
                Err(_) => break,     // timeout — client done sending
            }
        }
        tracing::trace!(drained = drained_total, "drained 1.6 SLP request bytes");

        let cached = self.state.cached_status.load();
        // `cached.suffix` already supplies the closing brace of the outer
        // status object plus the players/description sections, so the
        // pre-suffix half must leave `version` open: `{"version":{...}`,
        // never `{"version":{...}}`.
        let json = format!(
            r#"{{"version":{{"name":"Koja","protocol":{}}}{}"#,
            78, // 1.6.4 protocol
            cached.suffix
        );

        let legacy_motd = ClientboundLegacyMotd::from_json(&json);
        let response = legacy_motd.encode_legacy();

        self.stream
            .write_all(&response)
            .await
            .map_err(ConnectionError::Io)?;
        self.stream.flush().await.map_err(ConnectionError::Io)?;

        // Hand the client a moment to drain its receive buffer before
        // we close. Without this on Windows the OS occasionally raises
        // RST mid-read because we're closing the socket too fast after
        // the write. 50ms is empirically enough; the Notchian client
        // closes its end well before then.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        tracing::debug!(
            response_bytes = response.len(),
            "sent legacy 0xFE ping response to pre-1.7 client"
        );
        Ok(())
    }

    async fn handle_login(
        &mut self,
        original_host: String,
    ) -> Result<SharedSession, ConnectionError> {
        // Read LoginStart as raw bytes so we can parse the trailing UUID for
        // modern (1.19.3+) clients out of the *same* packet.  Reading a second
        // packet (as the old code did) deadlocks because the client doesn't
        // send anything until it receives EncryptionRequest / LoginSuccess.
        // See https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Start
        let raw_login_start = match tokio::time::timeout(
            tokio::time::Duration::from_secs(10),
            self.read_raw_packet_bytes(),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(ConnectionError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "login start timed out",
                )))
            },
        };

        let mut cursor = raw_login_start;
        let _pkt_id = VarInt::decode(&mut cursor).map_err(ConnectionError::Protocol)?;
        let username = String::decode(&mut cursor).map_err(ConnectionError::Protocol)?;

        let pv = nearest(self.protocol_version);
        let client_uuid = if pv.has_login_start_uuid() {
            let uuid_decode_err = || ConnectionError::Auth("failed to decode client UUID".into());

            // 1.19.3 (761) … 1.20.1 (763): optional UUID with a bool prefix.
            // 1.20.2+ (764+): UUID is mandatory and inlined.
            if !pv.has_mandatory_login_start_uuid() {
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
                    // CRITICAL: only mutate `self.compression_threshold`
                    // if the SetCompression packet was actually emitted
                    // to the client. 1.6.x and 1.7.x have no
                    // SetCompression packet (added in 1.8 = proto 47
                    // per minecraft.wiki), so
                    // `send_set_compression_with_threshold` skips on
                    // those epochs — and we must NOT enable compression
                    // framing on a client that never agreed to it.
                    //
                    // Without this guard, every subsequent limbo packet
                    // got a `VarInt(0)` uncompressed-marker prefix on
                    // the wire. The 1.7.x client reads that leading 0x00
                    // as packet id 0x00 (KeepAlive) and reports
                    // "Packet 0 has N extra bytes" before disconnecting
                    // — exactly the symptom in the user-reported log
                    // (JoinGame + PlayerAbilities then immediate abort).
                    self.send_set_compression_with_threshold(threshold).await?;
                    let ep = nearest(self.protocol_version).epoch();
                    if ep != Epoch::PreNetty && ep != Epoch::V1_7 {
                        self.compression_threshold = threshold;
                    } else {
                        tracing::debug!(
                            protocol = self.protocol_version,
                            "pre-1.8 client — leaving compression_threshold at NO_COMPRESSION so wire framing matches"
                        );
                    }
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

        let (enc_shared_secret, enc_verify_token) = match tokio::time::timeout(
            tokio::time::Duration::from_secs(10),
            self.recv_encryption_response(),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(ConnectionError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "encryption response timed out",
                )))
            },
        };

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
                    // CRITICAL: only mutate `self.compression_threshold`
                    // if the SetCompression packet was actually emitted
                    // to the client. 1.6.x and 1.7.x have no
                    // SetCompression packet (added in 1.8 = proto 47
                    // per minecraft.wiki), so
                    // `send_set_compression_with_threshold` skips on
                    // those epochs — and we must NOT enable compression
                    // framing on a client that never agreed to it.
                    //
                    // Without this guard, every subsequent limbo packet
                    // got a `VarInt(0)` uncompressed-marker prefix on
                    // the wire. The 1.7.x client reads that leading 0x00
                    // as packet id 0x00 (KeepAlive) and reports
                    // "Packet 0 has N extra bytes" before disconnecting
                    // — exactly the symptom in the user-reported log
                    // (JoinGame + PlayerAbilities then immediate abort).
                    self.send_set_compression_with_threshold(threshold).await?;
                    let ep = nearest(self.protocol_version).epoch();
                    if ep != Epoch::PreNetty && ep != Epoch::V1_7 {
                        self.compression_threshold = threshold;
                    } else {
                        tracing::debug!(
                            protocol = self.protocol_version,
                            "pre-1.8 client — leaving compression_threshold at NO_COMPRESSION so wire framing matches"
                        );
                    }
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
        mut properties: Vec<kojacoord_auth::ProfileProperty>,
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

        // ── Profile-property caching / skin recovery ─────────────────
        //
        // Two cases the proxy needs to handle around the dead pre-1.7
        // Mojang auth endpoint:
        //
        //  1. Online-mode 1.7+ login → Mojang-verified properties on
        //     hand. **Verify the signatures** against
        //     `[proxy.mojang_public_key]` and then **cache** the
        //     (uuid, username, properties) tuple so we can hand it back
        //     to a future 1.6.x connection.
        //
        //  2. Pre-netty 1.6.x login → no Mojang auth, no skin. **Load**
        //     the cached profile by username (the only key 1.6.x sends)
        //     and graft the cached signed property in so downstream
        //     limbo/relay code can synthesise the skin.
        //
        // Online-mode signature verification only runs when the proxy
        // is configured for online mode AND the client is post-1.6 (a
        // 1.6.x client never sent us a signature in the first place).
        let online_mode = self.state.config.proxy.online_mode;
        let canonical = nearest(self.protocol_version).canonical_typed_packet_version();
        let is_pre_netty_login = matches!(canonical, CanonicalVersion::V1_6_4);

        if online_mode && !is_pre_netty_login && !properties.is_empty() {
            match kojacoord_auth::parse_mojang_public_key(
                &self.state.config.proxy.mojang_public_key,
            ) {
                Ok(key) => match kojacoord_auth::verify_properties(&properties, &key, true) {
                    Ok(n) => {
                        tracing::debug!(
                            username = %username,
                            verified = n,
                            "Mojang property signatures verified"
                        );
                        if let Some(db) = &self.state.db {
                            if let Err(e) =
                                db.cache_player_profile(uuid, &username, &properties).await
                            {
                                tracing::warn!(error = %e, "failed to cache verified profile");
                            }
                        }
                    },
                    Err(e) => {
                        // A bad signature in online mode means someone
                        // is forging properties. Reject the login —
                        // skipping this check would let a MITM inject
                        // arbitrary skin/cape data.
                        let reason = serde_json::json!({
                            "text": format!("Profile signature check failed: {}", e),
                            "color": "red"
                        })
                        .to_string();
                        let _ = self.send_disconnect_login(&reason).await;
                        tracing::warn!(
                            username = %username,
                            error = %e,
                            "rejected login: Mojang property signature invalid"
                        );
                        return Err(ConnectionError::Auth(format!("bad signature: {}", e)));
                    },
                },
                Err(e) => {
                    // Misconfigured key. Log loudly but allow the login —
                    // failing closed here would lock everyone out.
                    tracing::error!(error = %e, "mojang_public_key in config does not parse");
                },
            }
        }

        // Pre-netty (1.6.x) path: pull whatever signed properties we
        // cached for this username from a previous 1.7+ login. The
        // cached `value`/`signature` base64 strings round-trip
        // verbatim, so a 1.7+ relay-target that re-verifies the
        // signature will see the same bytes Mojang signed.
        if is_pre_netty_login && properties.is_empty() {
            if let Some(db) = &self.state.db {
                match db.load_cached_profile_by_username(&username).await {
                    Ok(Some((_cached_uuid, cached_props))) => {
                        tracing::info!(
                            username = %username,
                            count = cached_props.len(),
                            "restored cached skin properties for 1.6.x login (Mojang auth unreachable for pre-1.7)"
                        );
                        properties = cached_props;
                    },
                    Ok(None) => {
                        tracing::debug!(
                            username = %username,
                            "no cached profile for 1.6.x login — player will appear with default skin"
                        );
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to load cached profile");
                    },
                }
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
            cookies: crate::cookies_transfers::CookieStore::default(),
        }));

        self.state.sessions.insert(uuid, session.clone());

        // Register player for metrics tracking. Returns an Arc handle so
        // the relay can record per-packet stats with a single atomic
        // increment (no lock taken on the hot path).
        let _player_metrics_handle = self.state.player_metrics.register_player(uuid);

        // Send resource pack if configured
        if let (Some(url), Some(hash)) = (
            &self.state.config.proxy.resource_pack_url,
            &self.state.config.proxy.resource_pack_hash,
        ) {
            use crate::resource_pack::{build_resource_pack_packet, should_send_resource_pack};

            if should_send_resource_pack(
                &self.state.config.proxy.resource_pack_url,
                &self.state.config.proxy.resource_pack_hash,
            ) {
                match build_resource_pack_packet(
                    url,
                    hash,
                    self.state.config.proxy.resource_pack_required,
                    self.state.config.proxy.resource_pack_prompt.as_deref(),
                    self.protocol_version,
                ) {
                    Ok(packet) => {
                        if let Err(e) = crate::packet_io::write_packet(
                            &mut self.stream,
                            &packet,
                            self.compression_threshold,
                        )
                        .await
                        {
                            tracing::warn!(error = %e, "Failed to send resource pack");
                        } else {
                            tracing::debug!(url = %url, "Sent resource pack to player");
                        }
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to build resource pack packet");
                    },
                }
            }
        }

        // Notify plugins that a player joined. A plugin may veto the join by
        // returning a KickPlayer response for this player.
        let join_kicked = self
            .state
            .dispatch_plugin_event(kojacoord_plugin_system::PluginEvent::PlayerJoin {
                uuid,
                username: username.clone(),
            })
            .await;

        if !join_kicked {
            let analytics = self.state.analytics.clone();
            let analytics_username = username.clone();
            tokio::spawn(async move {
                analytics.record_event(kojacoord_metrics::AnalyticsEvent {
                    timestamp: chrono::Utc::now(),
                    event_type: kojacoord_metrics::EventType::PlayerJoin,
                    data: serde_json::json!({ "uuid": uuid.to_string(), "username": analytics_username }),
                }).await;
            });
        }

        if join_kicked {
            self.state.sessions.remove(&uuid);
            if let Err(e) = self
                .send_play_disconnect(r#"{"text":"You were not allowed to join.","color":"red"}"#)
                .await
            {
                tracing::debug!(error = %e, "failed sending plugin-veto disconnect");
            }
            return Err(ConnectionError::Auth("join rejected by plugin".into()));
        }

        let backend_result = self
            .connect_to_backend(&username, session.clone(), &original_host, uuid)
            .await;

        let (backend, backend_threshold) = match backend_result {
            Ok(b) => b,
            Err(e) => {
                {
                    self.state.sessions.remove(&uuid);
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

        // Now in play state — any error from here on triggers a
        // play-state Disconnect via `send_graceful_kick`.
        self.conn_state = ConnectionState::Play;

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
                Ok(crate::relay::RelayExit::BackendKicked {
                    client_stream,
                    reason,
                }) => {
                    tracing::info!(
                        reason = %reason,
                        "backend kicked player — falling back to limbo"
                    );
                    self.stream = client_stream;
                    // Send the kick reason as a system chat message
                    // so the player understands why they ended up
                    // in limbo. Best-effort: ignore failures.
                    let chat_text = format!(
                        "You were kicked from the server: {}",
                        crate::packet_builder::plaintext_from_chat_json(&reason)
                    );
                    let raw = crate::packet_builder::build_system_message_packet(
                        &chat_text,
                        self.protocol_version,
                    );
                    let _ = crate::packet_io::write_packet(
                        &mut self.stream,
                        &raw,
                        self.compression_threshold,
                    )
                    .await;

                    // Pick a fallback target. Prefer the routing rules'
                    // current choice; if that's unavailable the limbo
                    // inside switch_to_server will keep us connected
                    // until something comes back.
                    let fallback_target = self
                        .state
                        .routing
                        .select(&self.state.server_registry)
                        .map(|s| s.name.clone())
                        .unwrap_or_default();

                    match self
                        .switch_to_server(
                            &fallback_target,
                            session.clone(),
                            &username,
                            &original_host,
                            uuid,
                        )
                        .await
                    {
                        Ok((new_backend, new_threshold)) => {
                            backend = new_backend;
                            backend_threshold = new_threshold;
                            continue;
                        },
                        Err(e) => break Err(e),
                    }
                },
                Err(e) => break Err(e),
            }
        };

        self.state.sessions.remove(&uuid);

        // Unregister player from metrics tracking
        self.state.player_metrics.unregister_player(uuid).await;

        // Notify plugins that the player left (fire-and-forget).
        let _ = self
            .state
            .dispatch_plugin_event(kojacoord_plugin_system::PluginEvent::PlayerLeave { uuid })
            .await;

        let analytics = self.state.analytics.clone();
        tokio::spawn(async move {
            analytics
                .record_event(kojacoord_metrics::AnalyticsEvent {
                    timestamp: chrono::Utc::now(),
                    event_type: kojacoord_metrics::EventType::PlayerLeave,
                    data: serde_json::json!({ "uuid": uuid.to_string() }),
                })
                .await;
        });

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
        let server_compression = server
            .as_ref()
            .map(|s| s.compression_threshold)
            .unwrap_or(0);

        self.send_backend_handshake(
            &mut backend,
            original_host,
            username,
            uuid,
            &props,
            &mode,
            &backend_type,
            server_compression,
        )
        .await?;
        let backend_protocol = self.backend_protocol_for(Some(target));
        let backend_threshold = self
            .complete_backend_login(
                &mut backend,
                backend_protocol,
                username,
                uuid,
                &props,
                &mode,
            )
            .await?;

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
        // Per https://minecraft.wiki/w/Java_Edition_protocol/Packets — the
        // SetCompression login packet was introduced in 1.8 (protocol 47).
        // 1.6.x (pre-netty) has no packet framing layer at all and 1.7.x
        // has framing but no compression negotiation. Sending the 1.8
        // packet to either is a wire-format violation; the client treats
        // the unexpected bytes as a malformed packet and disconnects.
        //
        // `build_set_compression` returns `None` for those two epochs,
        // so the explicit epoch check below is defence-in-depth (and
        // gives us a tracing breadcrumb for the skip).
        if ver.epoch() == Epoch::PreNetty || ver.epoch() == Epoch::V1_7 {
            tracing::debug!(
                protocol = proto,
                "skipping SetCompression for pre-1.8 client (compression not supported)"
            );
            return Ok(());
        }
        let canonical = ver.canonical_typed_packet_version();
        if let Some(pkt) = crate::login_packets::build_set_compression(canonical, proto, threshold)
        {
            self.write_raw_login_packet(pkt).await
        } else {
            Ok(())
        }
    }

    async fn send_login_success(
        &mut self,
        uuid: Uuid,
        username: &str,
        properties: &[kojacoord_auth::ProfileProperty],
    ) -> Result<(), ConnectionError> {
        let proto = self.protocol_version;
        let canonical = nearest(proto).canonical_typed_packet_version();
        tracing::debug!(
            username,
            uuid = %uuid,
            protocol = proto,
            "sending LoginSuccess"
        );
        // 1.6.4 pre-netty has a completely different `LoginRequestS2C`
        // shape AND framing. The packet goes out as raw bytes
        // `[0x01][entity_id i32][level_type UCS-2][gamemode u8]
        //  [dimension i8][difficulty u8][world_height u8][max_players u8]`
        // — no length VarInt, no packet-id VarInt, no compression. The
        // previous code path here used `write_typed`, which routes
        // through the modern `write_packet` framing and so produces a
        // packet the 1.6.4 client cannot parse (it reads the leading
        // length VarInt as a garbage packet id and disconnects).
        if matches!(canonical, CanonicalVersion::V1_6_4) {
            // Pre-netty's analogue of LoginSuccess + JoinGame is the
            // single Packet1Login. The 1.6 client treats this as both
            // "auth complete" and "spawn in the world", so the values
            // we set here are what limbo would otherwise have to
            // overwrite — we use the limbo defaults (flat, spectator)
            // directly instead of bouncing through two Packet1Login
            // frames in a row.
            //
            // Wire shape per HexaCord `Packet1Login::write`:
            //   `[0x01][entity_id i32][level_type UCS-2][gamemode u8]`
            //   `[dimension i8][difficulty u8][world_height u8][max_players u8]`
            // No length VarInt, no packet-id VarInt, no compression.
            use kojacoord_protocol::codec::Encode;
            use kojacoord_protocol::versions::v1_6_x::login::LoginRequestS2C;
            let pkt = LoginRequestS2C {
                entity_id: 0,
                level_type: "flat".to_string(),
                game_mode: 3, // spectator — no inventory, no damage
                dimension: 0,
                difficulty: 0,
                // `world_height` is the "unused" byte field per HexaCord's
                // `Packet1Login`. The 1.6.4 client never reads it; sending
                // 0 keeps the wire frame minimal.
                world_height: 0,
                max_players: 20,
            };
            let mut wire = BytesMut::new();
            wire.put_u8(0x01);
            pkt.encode(&mut wire)?;
            return crate::packet_io::write_legacy_bytes(&mut self.stream, &wire).await;
        }
        let profile = crate::login_packets::LoginProfile {
            uuid,
            username,
            properties,
        };
        if let Some(pkt) = crate::login_packets::build_login_success(canonical, proto, &profile) {
            self.write_raw_login_packet(pkt).await
        } else {
            Ok(())
        }
    }

    async fn send_encryption_request(
        &mut self,
        der_public_key: &[u8],
        verify_token: &[u8],
    ) -> Result<(), ConnectionError> {
        let proto = self.protocol_version;
        let canonical = nearest(proto).canonical_typed_packet_version();
        let built = crate::login_packets::build_encryption_request(
            canonical,
            proto,
            "",
            der_public_key,
            verify_token,
        );
        if let Some(pkt) = built {
            self.write_raw_login_packet(pkt).await
        } else {
            Ok(())
        }
    }

    async fn recv_encryption_response(&mut self) -> Result<(Vec<u8>, Vec<u8>), ConnectionError> {
        use bytes::Buf;
        let mut bytes =
            crate::packet_io::read_packet(&mut self.stream, self.compression_threshold).await?;
        let _id = VarInt::decode(&mut bytes)?;
        // 1.7.x kept Short(i16) length-prefixes on the encryption byte arrays;
        // 1.8+ uses VarInt. Reading the wrong shape yields a garbage length
        // (e.g. VarInt(128)=0x80 0x01 read as i16 = -32767 → "Smaller key
        // than nothing" disconnect on the client).
        let epoch = nearest(self.protocol_version).epoch();
        if matches!(epoch, Epoch::V1_7) {
            if bytes.remaining() < 2 {
                return Err(ConnectionError::Protocol(
                    kojacoord_protocol::ProtocolError::UnexpectedEof,
                ));
            }
            let ss_len = bytes.get_i16() as usize;
            let ss: Vec<u8> = bytes.split_to(ss_len).to_vec();
            if bytes.remaining() < 2 {
                return Err(ConnectionError::Protocol(
                    kojacoord_protocol::ProtocolError::UnexpectedEof,
                ));
            }
            let vt_len = bytes.get_i16() as usize;
            let vt: Vec<u8> = bytes.split_to(vt_len).to_vec();
            Ok((ss, vt))
        } else {
            let ss_len = VarInt::decode(&mut bytes)?.0 as usize;
            let ss: Vec<u8> = bytes.split_to(ss_len).to_vec();
            let vt_len = VarInt::decode(&mut bytes)?.0 as usize;
            let vt: Vec<u8> = bytes.split_to(vt_len).to_vec();
            Ok((ss, vt))
        }
    }

    async fn send_disconnect_login(&mut self, reason_json: &str) -> Result<(), ConnectionError> {
        let proto = self.protocol_version;
        let canonical = nearest(proto).canonical_typed_packet_version();
        // 1.6.x has no login state and no JSON chat. Kick goes out as
        // packet 0xFF with a single UCS-2 length-prefixed string, sent
        // raw without the modern varint frame.
        if crate::packet_io::is_pre_netty_proto(proto) {
            use kojacoord_protocol::versions::v1_6_x::login::ClientboundLoginDisconnect;
            let plaintext = crate::packet_builder::plaintext_from_chat_json(reason_json);
            let pkt = ClientboundLoginDisconnect { reason: plaintext };
            let mut body = BytesMut::new();
            body.put_u8(0xFF);
            pkt.encode(&mut body)?;
            crate::packet_io::write_legacy_bytes(&mut self.stream, &body).await?;
            return Ok(());
        }
        if let Some(pkt) =
            crate::login_packets::build_login_disconnect(canonical, proto, reason_json)
        {
            self.write_raw_login_packet(pkt).await
        } else {
            Ok(())
        }
    }

    async fn send_play_disconnect(&mut self, reason_json: &str) -> Result<(), ConnectionError> {
        // Centralised in `login_packets::build_play_disconnect` —
        // collapses 7 inline canonical-version arms into a single
        // builder call so this site stays one-liner-clean alongside
        // `send_login_success` / `send_encryption_request` /
        // `send_set_compression_with_threshold`.
        let proto = self.protocol_version;
        let canonical = nearest(proto).canonical_typed_packet_version();
        if let Some(pkt) =
            crate::login_packets::build_play_disconnect(canonical, proto, reason_json)
        {
            self.write_raw_login_packet(pkt).await
        } else {
            Ok(())
        }
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

        let backend_opt = self
            .state
            .routing
            .select_with_region(&self.state.server_registry, Some(self.addr.ip()));

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
                        let server_compression = b.compression_threshold;
                        if let Err(e) = self
                            .send_backend_handshake(
                                &mut conn,
                                &fwd_host,
                                username,
                                uuid,
                                &props,
                                &mode,
                                &backend_type,
                                server_compression,
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
                        let backend_protocol = self.backend_protocol_for(Some(&server_name));
                        match self
                            .complete_backend_login(
                                &mut conn,
                                backend_protocol,
                                username,
                                uuid,
                                &props,
                                &mode,
                            )
                            .await
                        {
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
        // Route through the failover-aware path so a downed primary
        // gets transparently swapped for its currently-active standby.
        let selected_server = self.state.route_via_failover(Some(self.addr.ip())).await;
        let mode = self.effective_forwarding_mode(
            selected_server
                .as_ref()
                .and_then(|b| b.forwarding_override.clone()),
        );
        let backend_type = selected_server
            .as_ref()
            .map(|b| b.backend_type.clone())
            .unwrap_or_default();
        let server_compression = selected_server
            .as_ref()
            .map(|s| s.compression_threshold)
            .unwrap_or(0);
        self.send_backend_handshake(
            &mut backend,
            fwd_host,
            username,
            uuid,
            &props,
            &mode,
            &backend_type,
            server_compression,
        )
        .await?;
        let backend_protocol =
            self.backend_protocol_for(selected_server.as_ref().map(|b| b.name.as_str()));
        let backend_threshold = self
            .complete_backend_login(
                &mut backend,
                backend_protocol,
                username,
                uuid,
                &props,
                &mode,
            )
            .await?;
        if let Some(b) = selected_server.as_ref() {
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
    /// Resolve the backend protocol the proxy expects to be speaking on the
    /// wire to the named target server. Used so login/encryption-request
    /// rewrites pick the right wire shape rather than blindly using the
    /// client's protocol. Falls back to:
    ///   * the lobby's configured `lobby_server_protocol` for the lobby
    ///   * the per-server `backend_protocol` if configured
    ///   * 1.12.2 (340) for V1_7 / V1_8 epoch clients with no explicit override
    ///   * the client's own protocol otherwise
    fn backend_protocol_for(&self, target_server: Option<&str>) -> u32 {
        let lobby_name = &self.state.config.proxy.lobby_server_name;
        let is_lobby = target_server
            .map(|name| name == lobby_name.as_str())
            .unwrap_or(false);

        if is_lobby {
            return self.state.config.proxy.lobby_server_protocol;
        }
        if let Some(name) = target_server {
            if let Some(srv) = self.state.config.servers.iter().find(|s| s.name == name) {
                if srv.backend_protocol > 0 {
                    return srv.backend_protocol;
                }
            }
        }
        match nearest(self.protocol_version).epoch() {
            Epoch::V1_7 | Epoch::V1_8 => ProtocolVersion::V1_12_2.id(),
            _ => self.protocol_version,
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
        _server_compression: i32,
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

        let handshake_address = match mode {
            kojacoord_config::ForwardingMode::Bungeecord => {
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
            },
            kojacoord_config::ForwardingMode::Velocity => {
                // Velocity modern forwarding uses a plugin message instead of
                // modifying the handshake address. The handshake uses the clean host.
                if is_forge_like {
                    modloader::apply_fml_marker(&clean_host, self.ml_session.kind)
                } else {
                    clean_host
                }
            },
            kojacoord_config::ForwardingMode::None => {
                if is_forge_like {
                    modloader::apply_fml_marker(&clean_host, self.ml_session.kind)
                } else {
                    clean_host
                }
            },
        };

        tracing::debug!(
            modloader = ?self.ml_session.kind,
            forwarding = ?mode,
            address_escaped = %handshake_address.replace('\0', "\\0"),
            address_len = handshake_address.len(),
            "sending backend handshake address"
        );

        // Centralised through `login_packets::build_backend_handshake` /
        // `build_backend_login_start` — collapses the inline 4-arm
        // canonical_version matches into the same builder pattern the
        // rest of connection.rs uses for clientbound login packets.
        let canonical = nearest(proto).canonical_typed_packet_version();

        if let Some(pkt) = crate::login_packets::build_backend_handshake(
            canonical,
            proto,
            handshake_address,
            25565,
        ) {
            let mut payload = BytesMut::new();
            VarInt(pkt.id as i32).encode(&mut payload)?;
            payload.extend_from_slice(&pkt.body);
            crate::packet_io::write_packet(conn, &payload, NO_COMPRESSION).await?;
        }

        if let Some(pkt) = crate::login_packets::build_backend_login_start(
            canonical,
            proto,
            username.to_string(),
            uuid,
        ) {
            let mut ls_payload = BytesMut::new();
            VarInt(pkt.id as i32).encode(&mut ls_payload)?;
            ls_payload.extend_from_slice(&pkt.body);
            crate::packet_io::write_packet(conn, &ls_payload, NO_COMPRESSION).await?;
        }

        Ok(())
    }

    async fn complete_backend_login(
        &mut self,
        conn: &mut TcpStream,
        backend_protocol: u32,
        username: &str,
        uuid: Uuid,
        properties: &[kojacoord_auth::ProfileProperty],
        mode: &kojacoord_config::ForwardingMode,
    ) -> Result<i32, ConnectionError> {
        let client_proto = self.protocol_version;
        let mut backend_threshold: i32 = NO_COMPRESSION;

        // All IDs used to *read* packets coming from the backend must be
        // looked up under the BACKEND's protocol (which is what the backend
        // is speaking on the wire), not the client's. Same for the wire-shape
        // we choose when decoding those packets. We only use the client's
        // protocol when we need to forward something to the client.
        // `backend_canonical` selects the right typed-packet module for
        // decoding things the BACKEND sends (e.g. LoginSuccess wire shape).
        // EncryptionRequest is shape-keyed off `Epoch::V1_7` vs everything
        // else, so it works with the epoch helper directly.
        let backend_canonical = nearest(backend_protocol).canonical_typed_packet_version();

        // Determine if backend has configuration phase (needed for Velocity plugin message)
        let backend_has_cfg = nearest(backend_protocol).has_configuration_phase();

        let id_set_compression = cb_login(backend_protocol, "ClientboundSetCompression");
        let id_login_success = cb_login(backend_protocol, "ClientboundLoginSuccess");
        let id_login_plugin = cb_login(backend_protocol, "ClientboundLoginPluginRequest");
        let id_login_plugin_sb = sb_login(backend_protocol, "ServerboundLoginPluginResponse");
        let id_login_ack = sb_login(backend_protocol, "ServerboundLoginAcknowledged");
        let id_cfg_ack = sb_config(backend_protocol, "AcknowledgeFinishConfiguration");
        let id_login_disconnect = cb_login(backend_protocol, "ClientboundLoginDisconnect");
        let id_encryption_request = cb_login(backend_protocol, "ClientboundEncryptionRequest");

        // What we forward to the client uses the client's IDs.
        let client_id_encryption_request = cb_login(client_proto, "ClientboundEncryptionRequest");

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
                let backend_epoch = nearest(backend_protocol).epoch();
                let client_epoch = nearest(client_proto).epoch();
                // The wire shape boundary for EncryptionRequest is Epoch::V1_7
                // vs everything else — we only need to rewrite when those
                // differ OR when the packet id differs between sides.
                let shape_differs = backend_epoch != client_epoch;
                let id_differs = backend_protocol != client_proto
                    && id_encryption_request != client_id_encryption_request;
                if shape_differs || id_differs {
                    let (server_id, public_key, verify_token) =
                        decode_encryption_request(backend_epoch, &mut cursor)
                            .map_err(ConnectionError::Protocol)?;

                    let mut new_payload = BytesMut::new();
                    VarInt(client_id_encryption_request as i32).encode(&mut new_payload)?;
                    encode_encryption_request(
                        client_epoch,
                        &server_id,
                        &public_key,
                        &verify_token,
                        &mut new_payload,
                    )?;
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
                // LoginSuccess wire shape changes per release (UUID-as-
                // string vs UUID-bytes, optional properties, optional
                // strict-error-handling). The skip is centralised in
                // `login_packets::skip_backend_login_success` so this
                // site doesn't need 7 inline arms; we don't care about
                // the field values because the proxy already issued its
                // own LoginSuccess to the client.
                crate::login_packets::skip_backend_login_success(backend_canonical, &mut cursor);

                // Velocity modern forwarding is a request/response flow
                // driven by the backend's `LoginPluginRequest` — we
                // respond inside the LoginPluginRequest handler below
                // when the channel is `velocity:player_info`. By the
                // time we see LoginSuccess that exchange has already
                // happened (or the backend isn't asking for it).
                break;
            } else if packet_id == id_login_plugin {
                use kojacoord_protocol::versions::v1_20_x::login::ServerboundLoginPluginResponse;

                let message_id = VarInt::decode(&mut cursor).map_err(ConnectionError::Protocol)?;
                let channel = String::decode(&mut cursor).map_err(ConnectionError::Protocol)?;
                let remaining: Vec<u8> = cursor.to_vec();

                tracing::debug!(
                    message_id = message_id.0,
                    channel    = %channel,
                    "backend LoginPluginRequest"
                );

                if channel == "velocity:player_info"
                    && matches!(mode, kojacoord_config::ForwardingMode::Velocity)
                {
                    // Backend (configured for Velocity modern forwarding)
                    // is asking us to prove the player. Sign the player
                    // info with the shared secret and reply via
                    // LoginPluginResponse — this is the canonical Velocity
                    // handshake. See <https://docs.papermc.io/velocity/security>.
                    let secret = &self.state.config.forwarding.velocity_secret;
                    if secret.is_empty() {
                        tracing::warn!(
                            "Velocity forwarding requested by backend but no secret configured"
                        );
                        let pkt = ServerboundLoginPluginResponse {
                            message_id,
                            data: vec![].into(),
                        };
                        let mut resp = BytesMut::new();
                        VarInt(id_login_plugin_sb as i32).encode(&mut resp)?;
                        pkt.encode(&mut resp)?;
                        crate::packet_io::write_packet(conn, &resp, backend_threshold).await?;
                    } else {
                        let profile = kojacoord_auth::AuthenticatedProfile {
                            id: uuid,
                            name: username.to_string(),
                            properties: properties.to_vec(),
                        };
                        let velocity_data = velocity_header(secret, &self.addr.ip(), &profile);
                        let pkt = ServerboundLoginPluginResponse {
                            message_id,
                            data: velocity_data.into(),
                        };
                        let mut resp = BytesMut::new();
                        VarInt(id_login_plugin_sb as i32).encode(&mut resp)?;
                        pkt.encode(&mut resp)?;
                        crate::packet_io::write_packet(conn, &resp, backend_threshold).await?;
                        tracing::debug!("Velocity LoginPluginResponse sent to backend");
                    }
                } else if modloader::is_fml3_login_channel(&channel) {
                    modloader::log_fml3_login_packet(&channel, &remaining, "S→C", backend_protocol);

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

        // Configuration phase exists from 1.20.2 (proto 764) onward. We enter
        // it only when BOTH sides speak it — otherwise the side that doesn't
        // would never send/expect LoginAcknowledged. The sibling converter
        // synthesises a fake FinishConfiguration when only one side has it.
        // See https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Acknowledged
        let client_has_cfg = nearest(client_proto).has_configuration_phase();
        if client_has_cfg && backend_has_cfg {
            {
                let actual =
                    crate::packet_io::read_packet(&mut self.stream, self.compression_threshold)
                        .await?;
                let mut cursor = actual;
                let pkt_id = VarInt::decode(&mut cursor)
                    .map_err(ConnectionError::Protocol)?
                    .0 as u8;
                // The LoginAck *we read* came from the client, so look up its
                // ID under the client's protocol.
                let expected = sb_login(client_proto, "ServerboundLoginAcknowledged");
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
                use kojacoord_protocol::versions::v1_20_x::login::ServerboundLoginAcknowledged;
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
                use kojacoord_protocol::versions::v1_20_x::config::ServerboundAcknowledgeFinishConfiguration;
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

        // Per-player rate limiting needs a UUID, but at this point in the
        // config phase the connection isn't yet bound to a session. Leave
        // the field as None — the rate limiter treats anonymous packets as
        // an aggregated bucket.
        let player_uuid: Option<uuid::Uuid> = None;

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

                        // Rate-limit plugin channel messages from client
                        if let Some(uuid) = player_uuid {
                            if !self.state.plugin_channel_rate_limiter.check(uuid).await {
                                // Drop the packet silently (rate-limited)
                                continue;
                            }
                        }
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
            use kojacoord_protocol::versions::v1_20_x::config::ClientboundFinishConfiguration;
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

        let backend_protocol = self.backend_protocol_for(current_server.as_deref());

        // Legacy clients always need conversion (their wire shape differs from
        // every modern backend); other clients need it whenever the lobby's
        // protocol doesn't match theirs. Epoch grouping makes "legacy" clean.
        let client_epoch = nearest(self.protocol_version).epoch();
        let conversion_enabled = (is_lobby && backend_protocol != self.protocol_version)
            || matches!(client_epoch, Epoch::PreNetty | Epoch::V1_7 | Epoch::V1_8);

        if conversion_enabled {
            tracing::debug!(
                client_proto  = self.protocol_version,
                backend_proto = backend_protocol,
                server        = %current_server.as_deref().unwrap_or("?"),
                "protocol conversion enabled"
            );
        }

        PacketRelay {
            client_stream: std::mem::replace(&mut self.stream, McStream::empty()),
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

    /// Write an already-encoded login-state packet (`id` + `body`)
    /// from [`crate::login_packets`].
    async fn write_raw_login_packet(
        &mut self,
        pkt: crate::login_packets::EncodedPacket,
    ) -> Result<(), ConnectionError> {
        let mut payload = BytesMut::new();
        VarInt(pkt.id as i32).encode(&mut payload)?;
        payload.extend_from_slice(&pkt.body);
        crate::packet_io::write_packet(&mut self.stream, &payload, self.compression_threshold)
            .await?;
        Ok(())
    }
}

/// Decode a ClientboundEncryptionRequest using the wire shape of `epoch`.
/// Returns (server_id, public_key bytes, verify_token bytes).
///
/// Per <https://minecraft.wiki/w/Java_Edition_protocol/Packets#Encryption_Request>:
/// 1.7.x (`Epoch::V1_7`) — String + i16-prefixed bytes + i16-prefixed bytes
/// 1.8+                  — String + VarInt-prefixed bytes + VarInt-prefixed bytes
/// 1.20.5+               — same but with a trailing should_authenticate bool we discard.
fn decode_encryption_request(
    epoch: Epoch,
    src: &mut Bytes,
) -> Result<(String, Vec<u8>, Vec<u8>), kojacoord_protocol::ProtocolError> {
    use bytes::Buf;
    let server_id = String::decode(src)?;
    if matches!(epoch, Epoch::V1_7) {
        // i16-prefixed byte arrays (netty-era 1.7.x).
        if src.remaining() < 2 {
            return Err(kojacoord_protocol::ProtocolError::UnexpectedEof);
        }
        let pk_len = src.get_i16() as usize;
        if src.remaining() < pk_len + 2 {
            return Err(kojacoord_protocol::ProtocolError::UnexpectedEof);
        }
        let public_key = src.split_to(pk_len).to_vec();
        let vt_len = src.get_i16() as usize;
        if src.remaining() < vt_len {
            return Err(kojacoord_protocol::ProtocolError::UnexpectedEof);
        }
        let verify_token = src.split_to(vt_len).to_vec();
        Ok((server_id, public_key, verify_token))
    } else {
        // VarInt-prefixed byte arrays (1.8 onward — every epoch from V1_8 up).
        let pk_len = VarInt::decode(src)?.0 as usize;
        if src.remaining() < pk_len {
            return Err(kojacoord_protocol::ProtocolError::UnexpectedEof);
        }
        let public_key = src.split_to(pk_len).to_vec();
        let vt_len = VarInt::decode(src)?.0 as usize;
        if src.remaining() < vt_len {
            return Err(kojacoord_protocol::ProtocolError::UnexpectedEof);
        }
        let verify_token = src.split_to(vt_len).to_vec();
        Ok((server_id, public_key, verify_token))
    }
}

/// Encode a ClientboundEncryptionRequest in the wire shape of `epoch`.
fn encode_encryption_request(
    epoch: Epoch,
    server_id: &str,
    public_key: &[u8],
    verify_token: &[u8],
    dst: &mut BytesMut,
) -> Result<(), kojacoord_protocol::ProtocolError> {
    use bytes::BufMut;
    server_id.to_string().encode(dst)?;
    if matches!(epoch, Epoch::V1_7) {
        dst.put_i16(public_key.len() as i16);
        dst.extend_from_slice(public_key);
        dst.put_i16(verify_token.len() as i16);
        dst.extend_from_slice(verify_token);
    } else {
        VarInt(public_key.len() as i32).encode(dst)?;
        dst.extend_from_slice(public_key);
        VarInt(verify_token.len() as i32).encode(dst)?;
        dst.extend_from_slice(verify_token);
    }
    Ok(())
}
