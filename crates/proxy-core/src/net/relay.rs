use bytes::BytesMut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use kojacoord_protocol::{codec::Encode, types::VarInt, Decode};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};

use crate::{
    commands,
    converter::{ConversionDirection, ConversionResult, PacketConverter},
    error::ConnectionError,
    exploit_guard::{build_kick_message, check_chat_message, ExploitGuard},
    modloader,
    packet_builder::{
        build_block_update_packet, build_brand_packet, build_disconnect_packet,
        build_plugin_message_packet, build_serverbound_plugin_message_packet,
        build_system_message_packet,
    },
    packet_ids::{cb_play, cb_plugin_message_id, chat_packet_ids_for, sb_plugin_message_id},
    packet_io::write_packet,
    plugin_decoder,
    proxy::ProxyState,
    server_selector,
    session::SharedSession,
    transfer,
};

use kojacoord_anticheat::{parse_serverbound, AnticheatPacket};
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
    pub ignore_movement_until: Option<tokio::time::Instant>,
}

#[allow(clippy::large_enum_variant)]
pub enum RelayExit {
    Disconnected,

    Switch {
        client_stream: crate::connection::McStream,
        target: String,
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

        match state.plugin_manager.process_packet(&packet_data) {
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
        let mut cr = crate::net::packet_io::ConnectionReader::new(cr);
        let (br, mut bw) = self.backend_stream.into_split();
        let mut br = crate::net::packet_io::ConnectionReader::new(br);

        let cw_master = Arc::new(Mutex::new(cw));
        let cw_s2c = Arc::clone(&cw_master);
        let cw_c2s = Arc::clone(&cw_master);

        let stop = Arc::new(Notify::new());
        let stopped = Arc::new(AtomicBool::new(false));
        let switch_target: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

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
        self.state.outbound.insert(player_uuid, out_tx);

        let (backend_out_tx, mut backend_out_rx) =
            tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
        self.state
            .backend_outbound
            .insert(player_uuid, backend_out_tx.clone());

        let (violation_tx, mut violation_rx) =
            tokio::sync::mpsc::unbounded_channel::<(String, String)>();

        let ignore_movement_until = self.ignore_movement_until;

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

        let cb_pm_id = cb_plugin_message_id(proto);
        let cb_disc_id = cb_play(proto, "ClientboundDisconnect");
        let sb_pm_id = sb_plugin_message_id(proto);
        let sb_chat_ids = chat_packet_ids_for(proto);

        let cb_chunk_id = cb_play(proto, "ClientboundLevelChunkWithLight");
        // BlockUpdate packet ID — used to intercept server-sent block changes
        // so we can remove honeypots that the real server has revealed.
        let cb_block_update_id: u8 = {
            use kojacoord_protocol::VersionRegistry;
            match VersionRegistry::nearest(proto) {
                kojacoord_protocol::ProtocolVersion::V1_7_10
                | kojacoord_protocol::ProtocolVersion::V1_8
                | kojacoord_protocol::ProtocolVersion::V1_12_2 => 0x23,
                kojacoord_protocol::ProtocolVersion::V1_16_5 => 0x0B,
                _ => 0x09, // 1.19+ and 1.21
            }
        };

        let state_s2c = Arc::clone(&self.state);
        let state_c2s = Arc::clone(&self.state);
        let xray_s2c = Arc::clone(&self.state.xray);
        let xray_c2s = Arc::clone(&self.state.xray);
        let session_s2c = self.session.clone();
        let session_c2s = self.session.clone();

        let s2c = async move {
            let result: Result<(), ConnectionError> = async move {
            loop {
                if stopped_s2c_chk.load(Ordering::Acquire) {
                    return Ok(());
                }
                let payload = tokio::select! {
                    biased;
                    _ = stop_s2c_wait.notified() => return Ok(()),
                    r = br_mut.read_packet(backend_thresh) => r?,
                };

                state_s2c.metrics.record_packet(payload.len());

                state_s2c.tps_tracker.record_packet();

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

                // ─── BlockUpdate intercept (S→C) ──────────────────────────
                // When the server reveals what a block actually is at a
                // position we have a honeypot, remove the honeypot so
                // the player can never get a false positive from it.
                if pkt_id == cb_block_update_id {
                    let mut body = payload.clone();
                    let _ = VarInt::decode(&mut body);
                    if let Ok(packed) = i64::decode(&mut body) {
                        use kojacoord_protocol::VersionRegistry;
                        let (bx, by, bz) = match VersionRegistry::nearest(proto) {
                            kojacoord_protocol::ProtocolVersion::V1_7_10
                            | kojacoord_protocol::ProtocolVersion::V1_8
                            | kojacoord_protocol::ProtocolVersion::V1_12_2 => {
                                // Legacy: X=63-38, Y=37-26, Z=25-0
                                let bx = (packed >> 38) as i32;
                                let by = ((packed >> 26) & 0xFFF) as i32;
                                let bz = ((packed << 38) >> 38) as i32;
                                (bx, by, bz)
                            },
                            _ => {
                                // 1.14+: X=63-38, Z=37-12, Y=11-0
                                let bx = (packed >> 38) as i32;
                                let by = ((packed << 52) >> 52) as i32;
                                let bz = ((packed << 26) >> 38) as i32;
                                (bx, by, bz)
                            }
                        };
                        xray_s2c.remove_honeypot(player_uuid, bx, by, bz);
                    }
                }

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
                    tracing::info!("backend sent Disconnect — sending custom message and closing relay");
                    let mut cw = cw_s2c.lock().await;

                    let limbo_message = "The server has shutdown, you are now in limbo until the server is back online.";
                    let pkt = build_disconnect_packet(limbo_message, proto);
                    write_packet(&mut *cw, &pkt, client_thresh).await?;

                    return Err(ConnectionError::Closed);
                }

                if conv_enabled && proto != backend_proto {
                    let direction = ConversionDirection::ServerToClient {
                        server_proto: backend_proto,
                        client_proto: proto,
                    };
                    match PacketConverter::convert(payload.clone(), direction) {
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
                        Some(req) = violation_rx.recv() => {
                            let uname = session_c2s.read().await.username.clone();
                            tracing::warn!(username = %uname, "anticheat violation detected (async): {} - {}", req.0, req.1);
                            kick!(
                                cw_c2s,
                                crate::exploit_guard::KickReason::Custom(req.0, req.1),
                                proto,
                                client_thresh
                            );
                        }
                        backend_pkt = backend_out_rx.recv() => {
                            match backend_pkt {
                                Some(raw) => {
                                    write_packet(&mut *bw_mut, &raw, backend_thresh).await?;
                                    continue;
                                }
                                None => return Ok(()),
                            }
                        }
                        r = cr_mut.read_packet(client_thresh) => r?,
                    };

                    // Per-connection abuse guard: enforce inbound packet-rate and
                    // per-packet size ceilings before any further processing.
                    if let Err(reason) = exploit_guard.check_packet(payload.len()) {
                        let username = session_c2s.read().await.username.clone();
                        tracing::warn!(username = %username, ?reason, "exploit_guard: kicking client");
                        kick!(cw_c2s, reason, proto, client_thresh);
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

                    let packet = parse_serverbound(&payload, proto);
                    let session_data = session_c2s.read().await;
                    let uuid = session_data.uuid;
                    let username = session_data.username.clone();
                    drop(session_data);
                    match packet {
                        // ─── XRay: player dug a honeypot block ───────────
                        AnticheatPacket::Dig(ref dig) if dig.status == 0 => {
                            let ac = Arc::clone(&xray_c2s);
                            let v_tx = violation_tx.clone();
                            let d_x = dig.x; let d_y = dig.y; let d_z = dig.z;
                            let uname = username.clone();
                            tokio::spawn(async move {
                                if let Some(_violation) = ac.check_dig(uuid, &uname, d_x, d_y, d_z).await {
                                    let _ = v_tx.send(("Anticheat Violation".to_string(), "XRay modification detected".to_string()));
                                }
                            });
                        },
                        // ─── Movement: honeypot injection + anticheat ─────
                        AnticheatPacket::Movement(ref movement) if movement.has_pos => {
                            if let Some(until) = ignore_movement_until {
                                if tokio::time::Instant::now() < until {
                                    tracing::trace!("dropping old movement packet during switch");
                                    continue;
                                }
                            }

                            // Inject honeypot blocks when the player is underground.
                            if movement.y < kojacoord_anticheat::xray::HONEYPOT_MAX_Y as f64 {
                                let new_honeypots = xray_c2s.spawn_honeypots(
                                    uuid,
                                    movement.x,
                                    movement.y,
                                    movement.z,
                                );
                                if !new_honeypots.is_empty() {
                                    let mut cw = cw_c2s.lock().await;
                                    for hp in &new_honeypots {
                                        let pkt = build_block_update_packet(
                                            hp.x, hp.y, hp.z,
                                            hp.block_state_id,
                                            proto,
                                        );
                                        if write_packet(&mut *cw, &pkt, client_thresh).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }

                            // Standard movement anticheat (offloaded to background task).
                            let ac = Arc::clone(&state_c2s.anticheat);
                            let v_tx = violation_tx.clone();
                            let uname = username.clone();
                            let m_x = movement.x; let m_y = movement.y; let m_z = movement.z;
                            let m_onground = movement.on_ground;

                            tokio::spawn(async move {
                                if let Some(violation) = ac.check_movement(uuid, &uname, m_x, m_y, m_z, m_onground, 0).await {
                                    let _ = v_tx.send(("Anticheat Violation".to_string(), format!("{} detected", violation.check_category.human_name())));
                                }
                            });
                        },
                        AnticheatPacket::Chat { message } if message.starts_with('/') => {},
                        _ => {},
                    }

                    if pkt_id == sb_pm_id {
                        let mut body = payload.clone();
                        let _ = VarInt::decode(&mut body);
                        if let Ok(msg) =
                            plugin_decoder::decode_serverbound_plugin_message(body, proto)
                        {
                            if msg.channel == "minecraft:brand" || msg.channel == "MC|Brand" {
                                if let Ok(brand) = String::from_utf8(msg.data.clone()) {
                                    let uuid = session_c2s.read().await.uuid;
                                    let ac = Arc::clone(&state_c2s.anticheat);
                                    tokio::spawn(async move {
                                        ac.register_mod_brand(uuid, brand).await;
                                    });
                                }
                            }

                            if modloader::is_fml1_play_channel(&msg.channel) {
                                modloader::log_fml1_packet(&msg.channel, &msg.data, "C→S", proto);
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

                                match result {
                                    commands::CommandResult::Handled => continue,
                                    commands::CommandResult::Switch(target) => {
                                        if request_switch(
                                            &target,
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
                                    _ => {} // Not a command or error
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

                    if conv_enabled && proto != backend_proto {
                        let direction = ConversionDirection::ClientToServer {
                            client_proto: proto,
                            server_proto: backend_proto,
                        };
                        match PacketConverter::convert(payload.clone(), direction) {
                            ConversionResult::Passthrough => {
                                write_packet(&mut *bw_mut, &payload, backend_thresh).await?;
                            },
                            ConversionResult::Converted(packets) => {
                                for pkt in packets {
                                    write_packet(&mut *bw_mut, &pkt, backend_thresh).await?;
                                }
                            },
                            ConversionResult::Drop => {
                                tracing::trace!(pkt_id, "C→S dropped by converter");
                            },
                        }
                    } else {
                        write_packet(&mut *bw_mut, &payload, backend_thresh).await?;
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
        // Clean up XRay honeypot state for this player.
        self.state.xray.player_quit(player_uuid);

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
