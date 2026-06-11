//! Play-phase packet pump.
//!
//! Once `ClientConnection` finishes the login dance, [`PacketRelay::run`]
//! takes over: three tokio tasks share the same underlying sockets,
//! one per direction (client→server, server→client, and a writer
//! that drains an mpsc of injected packets back to the client).
//! Tasks coordinate shutdown via a single `Notify`; the client
//! socket writer is a `tokio::sync::Mutex` shared between all three.
//!
//! On the hot path every S→C packet runs through:
//!   1. TPS tracker (lock-free atomic ring buffer)
//!   2. Per-player metrics atomic counters (handle cached at session
//!      start, no map lookup per packet)
//!   3. Optional cross-version packet converter
//!   4. Plugin packet hooks (`Forward` / `Drop` / `Modify`)
//!   5. Write to client
//!
//! The reverse direction adds a per-connection exploit guard
//! (`ExploitGuard`) on the way in. The `out_task` exists so plugins
//! and converters can inject packets toward the client without owning
//! the writer mutex themselves.

use bytes::BytesMut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use kojacoord_protocol::{codec::Encode, types::VarInt, Decode};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};

use crate::{
    chat_signing::{determine_signing_mode, strip_chat_signature},
    commands,
    config_synthesis::{build_cfg_finish_packet, determine_synthesis_mode, SynthesisMode},
    converter::{ConversionDirection, ConversionResult, PacketConverter},
    cookies_transfers::supports_cookies_transfers,
    error::ConnectionError,
    exploit_guard::{build_kick_message, check_chat_message, ExploitGuard, KickReason},
    modloader,
    packet_builder::{
        build_brand_packet, build_disconnect_packet, build_plugin_message_packet,
        build_serverbound_plugin_message_packet, build_system_message_packet,
    },
    packet_ids::{
        cb_play, cb_plugin_message_id, chat_packet_ids_for, sb_play, sb_plugin_message_id,
    },
    packet_io::{read_packet, write_packet},
    plugin_decoder,
    protocol::dimension_codec::{
        build_minimal_dimension_codec, determine_injection_mode, CodecInjectionMode,
    },
    proxy::ProxyState,
    server_selector,
    session::SharedSession,
    transfer,
};

use kojacoord_protocol::{Epoch, ProtocolVersion};

use kojacoord_plugin_system::{PacketData, PacketDirection, PacketHookResult};

pub struct PacketRelay {
    pub client_stream: crate::connection::McStream,
    pub backend_stream: TcpStream,
    pub session: SharedSession,
    pub state: Arc<ProxyState>,
    pub protocol_version: u32,
    pub client_compression_threshold: i32,
    pub backend_compression_threshold: i32,
    pub ml_kind: modloader::ModloaderKind,
    pub conversion_enabled: bool,
    pub backend_protocol: u32,
}

#[allow(clippy::large_enum_variant)]
pub enum RelayExit {
    Disconnected,

    Switch {
        client_stream: crate::connection::McStream,
        target: String,
    },

    /// Backend sent us a play-state Disconnect. We hand the client
    /// stream back to the outer pipeline so it can drop the player
    /// into limbo (or a fallback server) instead of closing the
    /// socket. `reason` is the JSON the backend gave us — surfaced
    /// to the player as a "you were kicked: …" message.
    BackendKicked {
        client_stream: crate::connection::McStream,
        reason: String,
    },
}

macro_rules! kick {
    ($cw:expr, $reason:expr, $proto:expr, $thresh:expr) => {{
        let msg = build_kick_message($reason);
        let pkt = build_disconnect_packet(&msg, $proto);
        let _ = write_packet(&mut *$cw.lock().await, &pkt, $thresh).await;
        return Err(ConnectionError::Closed);
    }};
}

impl PacketRelay {
    fn process_packet_hooks(
        state: &Arc<ProxyState>,
        protocol_version: u32,
        packet_id: i32,
        direction: PacketDirection,
        data: bytes::Bytes,
        player_uuid: uuid::Uuid,
    ) -> Result<bytes::Bytes, bytes::Bytes> {
        let packet_data = PacketData {
            protocol_version,
            packet_id,
            direction,
            data: data.clone(),
            player_uuid: Some(player_uuid),
        };

        let hook_result = state
            .plugin_manager
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .process_packet(&packet_data);
        match hook_result {
            PacketHookResult::Forward => Ok(data),
            PacketHookResult::Drop => Err(data),
            PacketHookResult::Modify(new_data) => Ok(new_data),
            PacketHookResult::Replace {
                packet_id: new_id,
                data: new_data,
            } => {
                let mut new_packet = BytesMut::new();
                let _ = VarInt(new_id).encode(&mut new_packet);
                new_packet.extend_from_slice(&new_data);
                Ok(new_packet.freeze())
            },
        }
    }

    pub async fn run(mut self) -> Result<RelayExit, ConnectionError> {
        let brand_raw = build_brand_packet(self.ml_kind, self.protocol_version);
        write_packet(
            &mut self.client_stream,
            &brand_raw,
            self.client_compression_threshold,
        )
        .await?;

        let (cr, cw) = tokio::io::split(self.client_stream);
        let mut cr = tokio::io::BufReader::with_capacity(8192, cr);
        let (br, mut bw) = self.backend_stream.into_split();
        let mut br = tokio::io::BufReader::with_capacity(8192, br);

        let cw_master = Arc::new(Mutex::new(cw));
        let cw_s2c = Arc::clone(&cw_master);
        let cw_c2s = Arc::clone(&cw_master);

        let stop = Arc::new(Notify::new());
        let stopped = Arc::new(AtomicBool::new(false));
        let switch_target: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        // Set when the backend sends us a play-state Disconnect — we
        // stash the reason and let the outer loop drop the player into
        // limbo instead of closing the client socket.
        let kick_reason: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let kick_reason_s2c = Arc::clone(&kick_reason);

        let stop_s2c_wait = Arc::clone(&stop);
        let stop_s2c_sig = Arc::clone(&stop);
        let stopped_s2c_chk = Arc::clone(&stopped);
        let stopped_s2c_set = Arc::clone(&stopped);

        let stop_c2s_wait = Arc::clone(&stop);
        let stop_c2s_sig = Arc::clone(&stop);
        let stopped_c2s_chk = Arc::clone(&stopped);
        let stopped_c2s_set = Arc::clone(&stopped);
        let switch_c2s = Arc::clone(&switch_target);

        let player_uuid = self.session.read().await.uuid;
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
        // Keep a clone in-scope for converter-driven s2c injection from the c2s
        // task (e.g. synthesizing FinishConfiguration after we swallow a
        // LoginAcknowledged from a 1.20.2+ client).
        let inject_s2c_tx = out_tx.clone();
        self.state.outbound.insert(player_uuid, out_tx);

        let (backend_out_tx, mut backend_out_rx) =
            tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
        self.state
            .backend_outbound
            .insert(player_uuid, backend_out_tx.clone());

        // Query pending purchases and deliver them immediately!
        if let Some(db) = &self.state.db {
            let db = Arc::clone(db);
            let username = self.session.read().await.username.clone();
            let backend_out_tx = backend_out_tx.clone();
            let proto = self.protocol_version;
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                if let Ok(purchases) = db.get_pending_purchases(&username).await {
                    for purchase in purchases {
                        let payload = purchase.product_slug.as_bytes();
                        let pkt_raw = build_serverbound_plugin_message_packet(
                            "kojacoord:purchase",
                            payload,
                            proto,
                        );
                        if backend_out_tx.send(pkt_raw).is_ok() {
                            let _ = db.mark_purchase_delivered(purchase.id).await;
                            tracing::info!(username = %username, product = %purchase.product_slug, "Delivered pending purchase to backend");
                        }
                    }
                }
            });
        }
        let cw_out = Arc::clone(&cw_master);
        let stop_out_wait = Arc::clone(&stop);
        let stop_out_sig = Arc::clone(&stop);
        let stopped_out_set = Arc::clone(&stopped);
        let stopped_out_chk = Arc::clone(&stopped);

        let cr_mut = &mut cr;
        let br_mut = &mut br;
        let bw_mut = &mut bw;

        let proto = self.protocol_version;
        let client_thresh = self.client_compression_threshold;
        let backend_thresh = self.backend_compression_threshold;
        let conv_enabled = self.conversion_enabled;
        let backend_proto = self.backend_protocol;

        // ViaVersion detection.
        //
        // ViaVersion-instrumented backends announce themselves to proxies
        // via a clientbound plugin message on the `vv:proxy_details` (or
        // `viaversion:proxy_details`) channel. When we see one we flip
        // this flag and skip our own per-packet converter for the rest of
        // the session — ViaVersion on the backend has already translated
        // every packet into the client's exact protocol, so any further
        // conversion on our side would corrupt the wire.
        //
        // Both directions check the same atomic, so detection in the
        // s2c loop flows immediately to the c2s loop's converter gate
        // without a lock.
        let via_version_detected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let via_version_detected_s2c = via_version_detected.clone();
        let via_version_detected_c2s = via_version_detected.clone();

        // Determine chat signing mode if enabled
        let chat_signing_mode = if self.state.config.proxy.chat_signing_translation {
            Some(determine_signing_mode(proto, backend_proto))
        } else {
            None
        };

        // Determine config synthesis mode
        let synthesis_mode = determine_synthesis_mode(proto, backend_proto);

        // Determine dimension codec injection mode
        let codec_injection_mode = determine_injection_mode(proto, backend_proto);

        // Check if cookies/transfers are supported
        let supports_cookies = supports_cookies_transfers(proto);

        let cb_pm_id = cb_plugin_message_id(proto);
        let cb_disc_id = cb_play(proto, "ClientboundDisconnect");
        let sb_pm_id = sb_plugin_message_id(proto);
        let sb_chat_ids = chat_packet_ids_for(proto);

        let cb_chunk_id = cb_play(proto, "ClientboundLevelChunkWithLight");
        // Look these up via the central registry so adding a new
        // protocol version (1.21.6+, …) doesn't require editing this
        // hot path.
        let sb_move_pos_id = sb_play(proto, "ServerboundMovePlayerPos");
        let sb_move_pos_rot_id = sb_play(proto, "ServerboundMovePlayerPosRot");

        let state_s2c = Arc::clone(&self.state);
        let state_c2s = Arc::clone(&self.state);
        let session_s2c = self.session.clone();
        let session_c2s = self.session.clone();

        // Lock-free per-player metrics handles. Grabbed once here; the
        // loops below just do `fetch_add` per packet, no locks taken on
        // the hot path. `None` means the player wasn't pre-registered
        // (shouldn't happen, but we skip silently if so).
        let metrics_handle = self.state.player_metrics.get(&player_uuid);
        let metrics_s2c = metrics_handle.clone();
        let metrics_c2s = metrics_handle.clone();
        // Microsecond clock shared by both directions; cheaper than
        // re-reading `Instant::now()` for every packet — we recompute
        // it once per loop iteration.
        let metrics_epoch = std::time::Instant::now();

        let s2c = async move {
            let result: Result<(), ConnectionError> = async move {
            loop {
                if stopped_s2c_chk.load(Ordering::Acquire) {
                    return Ok(());
                }
                let payload = tokio::select! {
                    biased;
                    _ = stop_s2c_wait.notified() => return Ok(()),
                    r = read_packet(&mut *br_mut, backend_thresh) => r?,
                };

                state_s2c.metrics.record_packet(payload.len());

                state_s2c.tps_tracker.record_packet();

                if let Some(m) = &metrics_s2c {
                    let now_micros = metrics_epoch.elapsed().as_micros() as u64;
                    crate::metrics_player::PlayerMetricsRegistry::record_sent(
                        m,
                        payload.len(),
                        now_micros,
                    );
                }

                let mut cur = payload.clone();

                let pkt_id = match VarInt::decode(&mut cur) {
                    Ok(v) => v.0 as u8,
                    Err(_) => {
                        let mut cw = cw_s2c.lock().await;
                        write_packet(&mut *cw, &payload, client_thresh).await?;
                        continue;
                    }
                };

                tracing::trace!(
                    direction = "S→C",
                    packet_id = pkt_id,
                    protocol = proto,
                    "packet"
                );

                if pkt_id == cb_chunk_id {
                    let mut cw = cw_s2c.lock().await;
                    write_packet(&mut *cw, &payload, client_thresh).await?;
                    continue;
                }

                if pkt_id == cb_pm_id {
                    let mut body = payload.clone();
                    let _ = VarInt::decode(&mut body);
                    if let Ok(msg) =
                        plugin_decoder::decode_clientbound_plugin_message(body, proto)
                    {
                        if msg.channel == "minecraft:brand" || msg.channel == "MC|Brand" {
                            tracing::debug!("suppressed backend brand");
                            continue;
                        }
                        if let Some(cmd) = transfer::parse_command(&msg.channel, &msg.data) {
                            if let Some(resp) =
                                handle_transfer_command(cmd, &session_s2c, &state_s2c).await
                            {
                                let pkt_raw = build_plugin_message_packet(
                                    transfer::KOJACOORD_CHANNEL,
                                    &resp,
                                    proto,
                                );
                                write_packet(&mut *cw_s2c.lock().await, &pkt_raw, client_thresh).await?;
                            }
                            continue;
                        }
                        if modloader::is_fml1_play_channel(&msg.channel) {
                            modloader::log_fml1_packet(&msg.channel, &msg.data, "S→C", proto);
                        }
                    }
                }

                if pkt_id == cb_disc_id {
                    // Backend kicked the player. Don't forward the
                    // disconnect — stash the reason, signal the relay
                    // to wind down cleanly, and let the outer pipeline
                    // hand the client off to limbo so they don't get
                    // dropped from the proxy.
                    let mut reason_cursor = payload.clone();
                    let _ = VarInt::decode(&mut reason_cursor); // skip the packet id
                    let reason = String::decode(&mut reason_cursor)
                        .unwrap_or_else(|_| "Backend disconnected".to_string());
                    tracing::info!(
                        reason = %reason,
                        "backend sent Disconnect — handing player to limbo"
                    );
                    *kick_reason_s2c.lock().await = Some(reason);
                    // Mirror what the outer post-block does — the
                    // outer scope still owns its own clones, so this
                    // just speeds up the stop signal.
                    return Ok(());
                }

                // ViaVersion detection: sniff clientbound plugin messages
                // for the `vv:proxy_details` channel. ViaVersion sends one
                // shortly after configuration to announce itself.
                if pkt_id == cb_pm_id {
                    if let Some(channel) = try_decode_plugin_channel(payload.clone()) {
                        if (channel == "vv:proxy_details"
                            || channel == "viaversion:proxy_details")
                            && !via_version_detected_s2c
                                .swap(true, std::sync::atomic::Ordering::AcqRel)
                        {
                            tracing::info!(
                                target: "relay",
                                channel = %channel,
                                proto,
                                backend_proto,
                                "ViaVersion detected on backend — disabling proxy-side converter for this session"
                            );
                        }
                    }
                }

                let convert_active = conv_enabled
                    && proto != backend_proto
                    && !via_version_detected_s2c
                        .load(std::sync::atomic::Ordering::Acquire);
                if convert_active {
                    let direction = ConversionDirection::ServerToClient {
                        server_proto: backend_proto,
                        client_proto: proto,
                    };
                    let repacker = Some(state_s2c.chunk_repacker.clone());
                    match PacketConverter::convert_with_repacker(payload.clone(), direction, repacker) {
                        ConversionResult::Passthrough => {
                            match Self::process_packet_hooks(
                                &state_s2c,
                                proto,
                                pkt_id as i32,
                                PacketDirection::Clientbound,
                                payload.clone(),
                                player_uuid,
                            ) {
                                Ok(data) => {
                                    let mut cw = cw_s2c.lock().await;
                                    write_packet(&mut *cw, &data, client_thresh).await?;
                                }
                                Err(_) => {
                                    tracing::trace!(pkt_id, "S→C dropped by plugin hook");
                                }
                            }
                        }
                        ConversionResult::Converted(packets) => {
                            let mut cw = cw_s2c.lock().await;
                            for pkt in packets {
                                let mut pkt_id_decoded = pkt.clone();
                                let pkt_id = VarInt::decode(&mut pkt_id_decoded).map(|v| v.0).unwrap_or(pkt_id as i32);
                                match Self::process_packet_hooks(
                                    &state_s2c,
                                    proto,
                                    pkt_id,
                                    PacketDirection::Clientbound,
                                    pkt,
                                    player_uuid,
                                ) {
                                    Ok(data) => {
                                        write_packet(&mut *cw, &data, client_thresh).await?;
                                    }
                                    Err(_) => {
                                        tracing::trace!(pkt_id, "S→C converted packet dropped by plugin hook");
                                    }
                                }
                            }
                        }
                        ConversionResult::Drop => {
                            tracing::trace!(pkt_id, "S→C dropped by converter");
                        }
                        ConversionResult::InjectS2C(_) => {
                            tracing::warn!(pkt_id, "S→C converter returned InjectS2C — only valid in C→S direction; dropping");
                        }
                    }
                } else {
                    match Self::process_packet_hooks(
                        &state_s2c,
                        proto,
                        pkt_id as i32,
                        PacketDirection::Clientbound,
                        payload.clone(),
                        player_uuid,
                    ) {
                        Ok(data) => {
                            let mut cw = cw_s2c.lock().await;
                            write_packet(&mut *cw, &data, client_thresh).await?;
                        }
                        Err(_) => {
                            tracing::trace!(pkt_id, "S→C dropped by plugin hook");
                        }
                    }
                }
            }

            #[allow(unreachable_code)]
            Ok::<(), ConnectionError>(())
            }.await;

            stopped_s2c_set.store(true, Ordering::Release);
            stop_s2c_sig.notify_waiters();
            result
        };

        let c2s = async move {
            let mut exploit_guard = ExploitGuard::new();
            let result: Result<(), ConnectionError> = async move {
                loop {
                    if stopped_c2s_chk.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    let payload = tokio::select! {
                        biased;
                        _ = stop_c2s_wait.notified() => return Ok(()),
                        backend_pkt = backend_out_rx.recv() => {
                            match backend_pkt {
                                Some(raw) => {
                                    write_packet(&mut *bw_mut, &raw, backend_thresh).await?;
                                    continue;
                                }
                                None => return Ok(()),
                            }
                        }
                        r = read_packet(&mut *cr_mut, client_thresh) => r?,
                    };

                    // Per-connection abuse guard: enforce inbound packet-rate and
                    // per-packet size ceilings before any further processing.
                    if let Err(reason) = exploit_guard.check_packet(payload.len()) {
                        let username = session_c2s.read().await.username.clone();
                        tracing::warn!(username = %username, ?reason, "exploit_guard: kicking client");
                        kick!(cw_c2s, reason, proto, client_thresh);
                    }

                    if let Some(m) = &metrics_c2s {
                        let now_micros = metrics_epoch.elapsed().as_micros() as u64;
                        crate::metrics_player::PlayerMetricsRegistry::record_received(
                            m,
                            payload.len(),
                            now_micros,
                        );
                    }

                    let mut cur = payload.clone();

                    let pkt_id = match VarInt::decode(&mut cur) {
                        Ok(v) => v.0 as u8,
                        Err(_) => {
                            tracing::warn!("exploit_guard: failed to decode packet id — kicking");
                            kick!(
                                cw_c2s,
                                crate::exploit_guard::KickReason::MalformedPacket,
                                proto,
                                client_thresh
                            );
                        },
                    };

                    tracing::trace!(
                        direction = "C→S",
                        packet_id = pkt_id,
                        protocol = proto,
                        "packet"
                    );

                    state_c2s.metrics.record_packet(payload.len());

                    let session_data = session_c2s.read().await;
                    let uuid = session_data.uuid;
                    drop(session_data);

                    // Dispatch movement events to plugin system (anticheat, etc.).
                    if pkt_id == sb_move_pos_rot_id || pkt_id == sb_move_pos_id {
                        let mut body = payload.clone();
                        let _ = VarInt::decode(&mut body);
                        if let (Ok(x), Ok(y), Ok(z)) = (
                            f64::decode(&mut body),
                            f64::decode(&mut body),
                            f64::decode(&mut body),
                        ) {
                            if pkt_id == sb_move_pos_rot_id {
                                let _ = f32::decode(&mut body);
                                let _ = f32::decode(&mut body);
                            }
                            let on_ground = bool::decode(&mut body).unwrap_or(false);
                            let responses = state_c2s
                                .plugin_manager
                                .read()
                                .unwrap_or_else(|e| e.into_inner())
                                .broadcast_event(
                                &kojacoord_plugin_system::PluginEvent::PlayerMove {
                                    uuid,
                                    x,
                                    y,
                                    z,
                                    on_ground,
                                },
                            );
                            for resp in responses {
                                if let kojacoord_plugin_system::PluginResponse::KickPlayer { uuid: kicked_uuid, reason } = resp {
                                    if kicked_uuid == uuid {
                                        kick!(
                                            cw_c2s,
                                            KickReason::Custom(
                                                "Anticheat Violation".to_string(),
                                                reason,
                                            ),
                                            proto,
                                            client_thresh
                                        );
                                    }
                                }
                            }
                        }
                    }

                    if pkt_id == sb_pm_id {
                        let mut body = payload.clone();
                        let _ = VarInt::decode(&mut body);
                        if let Ok(msg) =
                            plugin_decoder::decode_serverbound_plugin_message(body, proto)
                        {
                            if modloader::is_fml1_play_channel(&msg.channel) {
                                modloader::log_fml1_packet(&msg.channel, &msg.data, "C→S", proto);
                            }

                            // Cookies & Transfers passthrough handling
                            if supports_cookies && state_c2s.config.proxy.cookies_transfers_passthrough
                                && (msg.channel == "minecraft:cookie_response" || msg.channel == "minecraft:transfer") {
                                    tracing::trace!(channel = %msg.channel, "Passthrough: relaying cookie/transfer packet");
                                    // Store cookie data in session if needed
                                    let mut session = session_c2s.write().await;
                                    if msg.channel == "minecraft:cookie_response" {
                                        session.cookies.store("default".to_string(), msg.data.clone());
                                    }
                                    drop(session);
                                }

                            if server_selector::is_serverlist_channel(&msg.channel) {
                                let payload =
                                    server_selector::build_serverlist_payload(&state_c2s).await;

                                let pkt_raw =
                                    build_plugin_message_packet(&msg.channel, &payload, proto);
                                write_packet(&mut *cw_c2s.lock().await, &pkt_raw, client_thresh)
                                    .await?;
                                tracing::debug!(
                                    channel = %msg.channel,
                                    "server-selector: answered server-list request"
                                );
                                continue;
                            }
                            if server_selector::is_connect_channel(&msg.channel) {
                                if let Some(server) =
                                    server_selector::parse_connect_payload(&msg.data)
                                {
                                    if request_switch(
                                        &server,
                                        &state_c2s,
                                        &switch_c2s,
                                        &cw_c2s,
                                        proto,
                                        client_thresh,
                                    )
                                    .await?
                                    {
                                        return Ok(());
                                    }
                                } else {
                                    tracing::warn!(
                                        channel = %msg.channel,
                                        "server-selector: ignoring connect with empty server name"
                                    );
                                }
                                continue;
                            }
                            if server_selector::is_modpack_channel(&msg.channel) {
                                tracing::debug!(
                                    channel = %msg.channel,
                                    bytes = msg.data.len(),
                                    "server-selector: received modpack info"
                                );
                                continue;
                            }

                            if let Some(cmd) = transfer::parse_command(&msg.channel, &msg.data) {
                                if let transfer::TransferCommand::Connect { server } = &cmd {
                                    if request_switch(
                                        server,
                                        &state_c2s,
                                        &switch_c2s,
                                        &cw_c2s,
                                        proto,
                                        client_thresh,
                                    )
                                    .await?
                                    {
                                        return Ok(());
                                    }
                                    continue;
                                }
                                if let Some(resp) =
                                    handle_transfer_command(cmd, &session_c2s, &state_c2s).await
                                {
                                    let pkt_raw = build_plugin_message_packet(
                                        transfer::KOJACOORD_CHANNEL,
                                        &resp,
                                        proto,
                                    );
                                    write_packet(&mut *bw_mut, &pkt_raw, backend_thresh).await?;
                                }
                                continue;
                            }
                        }
                    }

                    // Chat signing translation: strip signatures if needed
                    let mut modified_payload = payload.clone();
                    if sb_chat_ids.contains(&pkt_id) {
                        let mut body = payload.clone();
                        let _ = VarInt::decode(&mut body);
                        if let Ok(text) = String::decode(&mut body) {
                            if let Err(reason) = check_chat_message(&text) {
                                let username = session_c2s.read().await.username.clone();
                                tracing::warn!(
                                    username = %username,
                                    "exploit_guard: illegal chat — kicking"
                                );
                                kick!(cw_c2s, reason, proto, client_thresh);
                            }

                            if let Some(mode) = chat_signing_mode {
                                use crate::chat_signing::ChatSigningMode;
                                if mode == ChatSigningMode::Unsigned {
                                    match strip_chat_signature(&payload, proto) {
                                        Ok(stripped) => {
                                            modified_payload = stripped.into();
                                            tracing::trace!("Stripped chat signature for unsigned mode");
                                        },
                                        Err(e) => {
                                            tracing::warn!(error = %e, "Failed to strip chat signature, using original");
                                        },
                                    }
                                }
                            }

                            // Deliver chat to plugins (handle_event). A plugin may
                            // request a kick, in which case we stop relaying.
                            if state_c2s
                                .dispatch_plugin_event(kojacoord_plugin_system::PluginEvent::PlayerChat {
                                    uuid,
                                    message: text.clone(),
                                })
                                .await
                            {
                                return Ok(());
                            }

                            if text.starts_with('/') {
                                let mut messages: Vec<String> = Vec::new();
                                let result = commands::handle_command(
                                    &text,
                                    session_c2s.clone(),
                                    Arc::clone(&state_c2s),
                                    &mut |msg| messages.push(msg),
                                )
                                .await;

                                if !messages.is_empty() {
                                    let mut cw = cw_c2s.lock().await;
                                    for msg in &messages {
                                        let encoded_raw = build_system_message_packet(msg, proto);
                                        if let Err(e) =
                                            write_packet(&mut *cw, &encoded_raw, client_thresh)
                                                .await
                                        {
                                            tracing::warn!(
                                                error = %e,
                                                "failed to send command response"
                                            );
                                        }
                                    }
                                }

                                if matches!(result, commands::CommandResult::Handled) {
                                    continue;
                                }
                            } else {
                                let (rank, name) = {
                                    let s = session_c2s.read().await;
                                    (s.rank.clone(), s.username.clone())
                                };
                                let line = state_c2s.roles.format_chat(&rank, &name, &text);
                                state_c2s.broadcast_system_message(&line).await;
                                continue;
                            }
                        }
                    }

                    // Same ViaVersion gate as the s2c loop above. Once
                    // the backend has identified itself as ViaVersion-
                    // backed, we leave c2s packets alone too — the
                    // backend will translate them itself.
                    let convert_active_c2s = conv_enabled
                        && proto != backend_proto
                        && !via_version_detected_c2s
                            .load(std::sync::atomic::Ordering::Acquire);
                    if convert_active_c2s {
                        let direction = ConversionDirection::ClientToServer {
                            client_proto: proto,
                            server_proto: backend_proto,
                        };
                        let payload_to_convert = if modified_payload != payload {
                            modified_payload.clone()
                        } else {
                            payload.clone()
                        };
                        let repacker = Some(state_c2s.chunk_repacker.clone());
                        match PacketConverter::convert_with_repacker(payload_to_convert.clone(), direction, repacker) {
                            ConversionResult::Passthrough => {
                                write_packet(&mut *bw_mut, &payload_to_convert, backend_thresh).await?;
                            },
                            ConversionResult::Converted(packets) => {
                                for pkt in packets {
                                    write_packet(&mut *bw_mut, &pkt, backend_thresh).await?;
                                }
                            },
                            ConversionResult::Drop => {
                                tracing::trace!(pkt_id, "C→S dropped by converter");
                            },
                            ConversionResult::InjectS2C(packets) => {
                                tracing::trace!(pkt_id, count = packets.len(), "C→S swallowed; injecting s2c packets back to client");
                                for pkt in packets {
                                    let _ = inject_s2c_tx.send(pkt);
                                }
                            },
                        }
                    } else {
                        // Config synthesis: inject FinishConfiguration if needed
                        if synthesis_mode == SynthesisMode::ClientSide {
                            // Check if this is a LoginAcknowledged packet (varies by protocol)
                            // For 1.20.2+, LoginAcknowledged is packet 0x03
                            let canonical = ProtocolVersion::from_id(proto);
                            if pkt_id == 0x03 && canonical.has_configuration_phase() {
                                tracing::trace!("Injecting synthetic FinishConfiguration packet");
                                if let Ok(cfg_finish) = build_cfg_finish_packet(proto) {
                                    let _ = inject_s2c_tx.send(cfg_finish.into());
                                }
                            }
                        }

                        // Dimension codec injection: inject codec data if needed
                        if codec_injection_mode == CodecInjectionMode::ClientSide {
                            // Check if this is a JoinGame packet
                            // JoinGame packet ID varies by protocol
                            let canonical = ProtocolVersion::from_id(proto);
                            let join_game_id = match canonical.epoch() {
                                Epoch::V1_19 => 0x26,
                                Epoch::V1_16 => 0x25,
                                Epoch::V1_17_To_1_18 => 0x25,
                                Epoch::V1_20 => 0x2B,
                                Epoch::V1_21Plus => 0x2E,
                                _ => 0x25, // fallback for older versions
                            };
                            if pkt_id == join_game_id {
                                tracing::trace!("Dimension codec injection needed for JoinGame");
                                // Build and inject minimal dimension codec
                                match build_minimal_dimension_codec() {
                                    Ok(codec_bytes) => {
                                        tracing::debug!("Injecting dimension codec NBT ({} bytes)", codec_bytes.len());
                                        // For 1.16-1.20.1, codec is embedded in JoinGame
                                        // For 1.20.2+, codec is sent separately via RegistryData packet
                                        // We'll inject it as a separate RegistryData packet for simplicity
                                        let registry_packet_id = match canonical.epoch() {
                                            Epoch::V1_21Plus => 0x05, // RegistryData in 1.21+
                                            _ => 0x04, // RegistryData in 1.20.2-1.20.5
                                        };

                                        let mut registry_packet = BytesMut::new();
                                        let _ = VarInt(registry_packet_id).encode(&mut registry_packet);
                                        registry_packet.extend_from_slice(&codec_bytes);

                                        // Inject the registry packet before JoinGame
                                        let _ = inject_s2c_tx.send(registry_packet.freeze());
                                    },
                                    Err(e) => {
                                        tracing::warn!(error = %e, "Failed to build dimension codec NBT");
                                    },
                                }
                            }
                        }

                        // Use modified payload if signature was stripped
                        let payload_to_send = if modified_payload != payload {
                            modified_payload.clone()
                        } else {
                            payload.clone()
                        };
                        write_packet(&mut *bw_mut, &payload_to_send, backend_thresh).await?;
                    }
                }

                #[allow(unreachable_code)]
                Ok::<(), ConnectionError>(())
            }
            .await;

            stopped_c2s_set.store(true, Ordering::Release);
            stop_c2s_sig.notify_waiters();
            result
        };

        let out_task = async move {
            loop {
                if stopped_out_chk.load(Ordering::Acquire) {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = stop_out_wait.notified() => break,
                    msg = out_rx.recv() => match msg {
                        Some(raw) => {
                            if write_packet(&mut *cw_out.lock().await, &raw, client_thresh).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    },
                }
            }
            stopped_out_set.store(true, Ordering::Release);
            stop_out_sig.notify_waiters();
        };

        let (c2s_res, s2c_res, _) = tokio::join!(c2s, s2c, out_task);

        self.state.outbound.remove(&player_uuid);
        self.state.backend_outbound.remove(&player_uuid);

        if let Some(srv_name) = self.session.read().await.current_server.clone() {
            if let Some(srv) = self.state.server_registry.get(&srv_name) {
                srv.player_count.fetch_sub(1, Ordering::Relaxed);
            }
        }
        self.session.write().await.current_server = None;

        let target = switch_target.lock().await.take();
        if let (Some(target), Ok(())) = (target, &c2s_res) {
            match Arc::try_unwrap(cw_master) {
                Ok(mutex) => {
                    let cw = mutex.into_inner();
                    let client_stream = cr.into_inner().unsplit(cw);
                    tracing::info!(target = %target, "relay: performing live server switch");
                    return Ok(RelayExit::Switch {
                        client_stream,
                        target,
                    });
                },
                Err(_) => {
                    tracing::error!("relay: could not reunite client stream for switch");
                    return Err(ConnectionError::Closed);
                },
            }
        }

        // Did the backend kick us mid-play? Hand the stream back to
        // the outer pipeline so it can drop the player into limbo.
        // The s2c task that detected the kick also set the stop
        // signal, so by here c2s has wound down naturally.
        let kick = kick_reason.lock().await.take();
        if let Some(reason) = kick {
            match Arc::try_unwrap(cw_master) {
                Ok(mutex) => {
                    let cw = mutex.into_inner();
                    let client_stream = cr.into_inner().unsplit(cw);
                    return Ok(RelayExit::BackendKicked {
                        client_stream,
                        reason,
                    });
                },
                Err(_) => {
                    tracing::error!("relay: could not reunite client stream after backend kick");
                    return Err(ConnectionError::Closed);
                },
            }
        }

        c2s_res?;
        s2c_res?;
        Ok(RelayExit::Disconnected)
    }
}

async fn request_switch<W>(
    server: &str,
    state: &Arc<ProxyState>,
    switch_target: &Mutex<Option<String>>,
    cw: &Mutex<W>,
    proto: u32,
    client_thresh: i32,
) -> Result<bool, ConnectionError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let reject = |reason: &str| format!(r#"{{"text":"{}","color":"red"}}"#, reason);

    let message = match state.server_registry.get(server) {
        Some(b) if b.is_online() => {
            *switch_target.lock().await = Some(server.to_owned());
            tracing::info!(server = %server, "relay: live switch requested");
            return Ok(true);
        },
        Some(_) => reject(&format!("Server '{}' is currently offline.", server)),
        None => reject(&format!("Unknown server '{}'.", server)),
    };

    let raw = build_system_message_packet(&message, proto);
    write_packet(&mut *cw.lock().await, &raw, client_thresh).await?;
    Ok(false)
}

async fn handle_transfer_command(
    cmd: transfer::TransferCommand,
    session: &SharedSession,
    state: &Arc<ProxyState>,
) -> Option<Vec<u8>> {
    match cmd {
        transfer::TransferCommand::Connect { server } => {
            match state.server_registry.get(&server) {
                Some(backend) => {
                    if let Some(old_name) = session.read().await.current_server.clone() {
                        if let Some(old) = state.server_registry.get(&old_name) {
                            old.player_count.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                    backend.player_count.fetch_add(1, Ordering::Relaxed);
                    session.write().await.current_server = Some(server.clone());
                    tracing::info!(server = %server, "relay: transfer requested");
                },
                None => tracing::warn!(%server, "relay: connect to unknown server ignored"),
            }
            None
        },
        transfer::TransferCommand::ConnectOther { server, uuid } => {
            if let Some(target) = state.sessions.get(&uuid) {
                if let Some(old_name) = target.read().await.current_server.clone() {
                    if let Some(old) = state.server_registry.get(&old_name) {
                        old.player_count.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                if let Some(new_srv) = state.server_registry.get(&server) {
                    new_srv.player_count.fetch_add(1, Ordering::Relaxed);
                }
                target.write().await.current_server = Some(server.clone());
                tracing::info!(%uuid, %server, "relay: ConnectOther transferred");
            } else {
                tracing::warn!(%uuid, %server, "relay: ConnectOther player not found");
            }
            None
        },
        transfer::TransferCommand::GetServer => {
            let name = session
                .read()
                .await
                .current_server
                .clone()
                .unwrap_or_else(|| "unknown".to_owned());
            serde_json::to_vec(&transfer::TransferResponse::CurrentServer { name }).ok()
        },
        transfer::TransferCommand::GetPlayers => {
            let players: Vec<String> = {
                state
                    .sessions
                    .iter()
                    .filter_map(|entry| entry.value().try_read().ok().map(|g| g.username.clone()))
                    .filter(|s| !s.is_empty())
                    .collect()
            };
            serde_json::to_vec(&transfer::TransferResponse::PlayerList {
                count: players.len(),
                players,
            })
            .ok()
        },
    }
}

/// Best-effort decode of a clientbound PluginMessage payload's channel
/// name. Returns `None` if the payload doesn't decode as a VarInt-id +
/// VarInt-prefixed UTF-8 channel — which is the case for almost every
/// non-plugin-message packet, so the caller passes a packet body and
/// this function safely returns `None` for bodies that aren't actually
/// plugin messages.
///
/// The shape we look for matches modern (1.13+) plugin messages:
/// `[VarInt id][VarInt channel_len][channel UTF-8 bytes][...payload]`.
/// Pre-1.13 plugin messages used a UCS-2 BE channel; those aren't
/// detected here, which is correct because ViaVersion's
/// `vv:proxy_details` channel only appears on modern (post-1.13)
/// connections where the proxy actually needs to translate.
fn try_decode_plugin_channel(payload: bytes::Bytes) -> Option<String> {
    use kojacoord_protocol::codec::Decode;
    let mut cur = payload;
    // Drop the leading packet id (VarInt).
    let _ = kojacoord_protocol::types::VarInt::decode(&mut cur).ok()?;
    // Channel name is the first VarInt-string field.
    String::decode(&mut cur).ok()
}
