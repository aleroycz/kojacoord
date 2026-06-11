//! `(protocol_version, state, direction, name) → packet_id` lookup.
//!
//! Built once at startup by `build_default_registry`, then queried by
//! the older string-based code paths in `connection.rs` and `relay.rs`.
//! Newer hot-path code uses the compile-time `PacketId` trait instead;
//! prefer that for any new call site since it dodges the hash lookup
//! and the typo risk.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolState {
    Handshake,
    Status,
    Login,
    Configuration,
    Play,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Serverbound,
    Clientbound,
}

#[derive(Debug, Clone)]
pub struct PacketMeta {
    pub id: u8,
    pub name: &'static str,
}

pub struct PacketRegistry {
    map: HashMap<ProtocolState, HashMap<Direction, Vec<(u32, PacketMeta)>>>,
}

impl PacketRegistry {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn register(
        &mut self,
        proto: u32,
        state: ProtocolState,
        dir: Direction,
        name: &'static str,
        id: u8,
    ) {
        let state_map = self.map.entry(state).or_default();
        let dir_vec = state_map.entry(dir).or_default();
        if let Some((_, meta)) = dir_vec
            .iter_mut()
            .find(|(p, meta)| *p == proto && meta.name == name)
        {
            meta.id = id;
        } else {
            dir_vec.push((proto, PacketMeta { id, name }));
        }
    }

    pub fn get_id(
        &self,
        proto: u32,
        state: ProtocolState,
        dir: Direction,
        name: &'static str,
    ) -> Option<u8> {
        let state_map = self.map.get(&state)?;
        let dir_vec = state_map.get(&dir)?;
        dir_vec
            .iter()
            .find(|(p, meta)| *p == proto && meta.name == name)
            .map(|(_, meta)| meta.id)
    }

    /// Look up a packet id for the given protocol, with fallback to the
    /// highest-numbered version that registered the packet at `proto` or
    /// lower. Lets us register an ID once per protocol bump and have it apply
    /// to every subversion in between.
    pub fn get_id_for_version(
        &self,
        proto: u32,
        state: ProtocolState,
        dir: Direction,
        name: &'static str,
    ) -> Option<u8> {
        let state_map = self.map.get(&state)?;
        let dir_vec = state_map.get(&dir)?;

        if let Some((_, meta)) = dir_vec
            .iter()
            .find(|(p, meta)| *p == proto && meta.name == name)
        {
            return Some(meta.id);
        }

        let mut best_proto: Option<u32> = None;
        let mut best_id: Option<u8> = None;
        for (p, meta) in dir_vec {
            if meta.name == name && *p <= proto && best_proto.map_or(true, |bp| *p > bp) {
                best_proto = Some(*p);
                best_id = Some(meta.id);
            }
        }
        best_id
    }

    pub fn get_name_from_id(
        &self,
        proto: u32,
        state: ProtocolState,
        dir: Direction,
        id: u8,
    ) -> Option<&'static str> {
        let state_map = self.map.get(&state)?;
        let dir_vec = state_map.get(&dir)?;

        if let Some((_, meta)) = dir_vec
            .iter()
            .find(|(p, meta)| *p == proto && meta.id == id)
        {
            return Some(meta.name);
        }

        let mut best_proto: Option<u32> = None;
        let mut best_name: Option<&'static str> = None;
        for (p, meta) in dir_vec {
            if meta.id == id && *p <= proto && best_proto.map_or(true, |bp| *p > bp) {
                best_proto = Some(*p);
                best_name = Some(meta.name);
            }
        }
        best_name
    }
}

impl Default for PacketRegistry {
    fn default() -> Self {
        build_default_registry()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Process-wide registry singleton + shorthand lookup helpers.
//
// Every typed-packet `PacketId::packet_id(ver)` impl delegates to one of
// these so the per-version id table lives in exactly one place (the const
// arrays below) instead of being duplicated as a `match ver { … }` inside
// every struct.
//
// The OnceLock is initialised on first access — cheap, lock-free reads
// after that.
// ─────────────────────────────────────────────────────────────────────────────

use std::sync::OnceLock;

static REGISTRY_SINGLETON: OnceLock<PacketRegistry> = OnceLock::new();

/// Return the process-wide [`PacketRegistry`]. Initialised on first call.
pub fn registry() -> &'static PacketRegistry {
    REGISTRY_SINGLETON.get_or_init(build_default_registry)
}

/// Look up a packet id by name. Returns `0xFF` if the (proto, state,
/// direction, name) tuple isn't registered — the same sentinel callers
/// already check against before sending.
#[inline]
pub fn lookup(proto: u32, state: ProtocolState, dir: Direction, name: &'static str) -> u8 {
    match registry().get_id_for_version(proto, state, dir, name) {
        Some(id) => {
            tracing::info!(proto, ?state, ?dir, name, id, "packet id resolved");
            id
        },
        None => {
            tracing::warn!(
                proto,
                ?state,
                ?dir,
                name,
                "packet id not found in registry, falling back to 0xFF"
            );
            0xFF
        },
    }
}

/// Shorthand for `lookup(proto, Play, Clientbound, name)`.
#[inline]
pub fn cb_play(proto: u32, name: &'static str) -> u8 {
    lookup(proto, ProtocolState::Play, Direction::Clientbound, name)
}

/// Shorthand for `lookup(proto, Play, Serverbound, name)`.
#[inline]
pub fn sb_play(proto: u32, name: &'static str) -> u8 {
    lookup(proto, ProtocolState::Play, Direction::Serverbound, name)
}

/// Shorthand for `lookup(proto, Login, Clientbound, name)`.
#[inline]
pub fn cb_login(proto: u32, name: &'static str) -> u8 {
    lookup(proto, ProtocolState::Login, Direction::Clientbound, name)
}

/// Shorthand for `lookup(proto, Login, Serverbound, name)`.
#[inline]
pub fn sb_login(proto: u32, name: &'static str) -> u8 {
    lookup(proto, ProtocolState::Login, Direction::Serverbound, name)
}

/// Shorthand for `lookup(proto, Configuration, Clientbound, name)`.
#[inline]
pub fn cb_config(proto: u32, name: &'static str) -> u8 {
    lookup(
        proto,
        ProtocolState::Configuration,
        Direction::Clientbound,
        name,
    )
}

/// Shorthand for `lookup(proto, Configuration, Serverbound, name)`.
#[inline]
pub fn sb_config(proto: u32, name: &'static str) -> u8 {
    lookup(
        proto,
        ProtocolState::Configuration,
        Direction::Serverbound,
        name,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry tables — IDs verified against https://minecraft.wiki packet pages.
//
// Only the packet names the proxy actually looks up are listed. Registering
// happens at the protocol version where each ID first appeared; subversions in
// between (e.g. 1.9.1/1.9.2/1.9.4 between 1.9=107 and 1.10=210) inherit via
// `get_id_for_version`'s nearest-lower-proto fallback.
//
// Sources used:
//   * https://minecraft.wiki/w/Java_Edition_protocol/Packets (current)
//   * https://minecraft.wiki/w/Java_Edition_protocol_history (per-version diff)
//   * https://minecraft.wiki/w/Java_Edition_protocol — older revisions for
//     pre-1.13 packets.
// ─────────────────────────────────────────────────────────────────────────────

type Entry = (u32, ProtocolState, Direction, &'static str, u8);

/// Pre-netty (1.6.x) — uses single-byte hardcoded IDs, no varint framing.
/// Kept here as a compatibility shim; the actual netty proxy never speaks this
/// state machine but downstream code still queries the names.
// Source <https://github.com/ProtocolSupport/ProtocolSupport/blob/master/src/protocolsupport/protocol/pipeline/version/v_1_6/PacketDecoder.java> (per-version diff)
const PRE_NETTY: &[Entry] = &[
    (
        78,
        ProtocolState::Login,
        Direction::Serverbound,
        "ServerboundPingRequest",
        0xFE,
    ),
    (
        78,
        ProtocolState::Login,
        Direction::Serverbound,
        "HandshakeC2S",
        0x02,
    ),
    (
        78,
        ProtocolState::Login,
        Direction::Clientbound,
        "EncryptionKeyRequestS2C",
        0xFD,
    ),
    (
        78,
        ProtocolState::Login,
        Direction::Serverbound,
        "EncryptionKeyResponseC2S",
        0xFC,
    ),
    (
        78,
        ProtocolState::Login,
        Direction::Clientbound,
        "LoginRequestS2C",
        0x01,
    ),
];

/// Handshake state: same for every netty version (1.7+) — single packet.
const HANDSHAKE: &[Entry] = &[(
    4,
    ProtocolState::Handshake,
    Direction::Serverbound,
    "ServerboundHandshake",
    0x00,
)];

/// Status state: stable across every netty version (1.7+).
const STATUS: &[Entry] = &[
    (
        4,
        ProtocolState::Status,
        Direction::Serverbound,
        "ServerboundStatusRequest",
        0x00,
    ),
    (
        4,
        ProtocolState::Status,
        Direction::Serverbound,
        "ServerboundPingRequest",
        0x01,
    ),
    (
        4,
        ProtocolState::Status,
        Direction::Clientbound,
        "ClientboundStatusResponse",
        0x00,
    ),
    (
        4,
        ProtocolState::Status,
        Direction::Clientbound,
        "ClientboundPongResponse",
        0x01,
    ),
];

/// Login state evolution.
///   1.7.x (4/5):   LoginStart 0x00, EncryptionResp 0x01,
///                  Disconnect 0x00, EncryptionReq 0x01, LoginSuccess 0x02
///   1.8 (47):      SetCompression 0x03 added
///   1.13 (393):    LoginPluginRequest 0x04 + LoginPluginResponse 0x02 added
///   1.20.2 (764):  LoginAcknowledged 0x03 added
const LOGIN: &[Entry] = &[
    (
        4,
        ProtocolState::Login,
        Direction::Serverbound,
        "ServerboundLoginStart",
        0x00,
    ),
    (
        4,
        ProtocolState::Login,
        Direction::Serverbound,
        "ServerboundEncryptionResponse",
        0x01,
    ),
    (
        4,
        ProtocolState::Login,
        Direction::Clientbound,
        "ClientboundLoginDisconnect",
        0x00,
    ),
    (
        4,
        ProtocolState::Login,
        Direction::Clientbound,
        "ClientboundEncryptionRequest",
        0x01,
    ),
    (
        4,
        ProtocolState::Login,
        Direction::Clientbound,
        "ClientboundLoginSuccess",
        0x02,
    ),
    (
        47,
        ProtocolState::Login,
        Direction::Clientbound,
        "ClientboundSetCompression",
        0x03,
    ),
    (
        393,
        ProtocolState::Login,
        Direction::Clientbound,
        "ClientboundLoginPluginRequest",
        0x04,
    ),
    (
        393,
        ProtocolState::Login,
        Direction::Serverbound,
        "ServerboundLoginPluginResponse",
        0x02,
    ),
    (
        764,
        ProtocolState::Login,
        Direction::Serverbound,
        "ServerboundLoginAcknowledged",
        0x03,
    ),
];

/// Configuration state — introduced in 1.20.2 (proto 764). 1.20.5
/// (proto 766) inserted Cookie Request at 0x00, shifting every following
/// id up by one. Only the names the proxy actually looks up are listed;
/// see `cb_config` / `sb_config` call sites in `connection.rs`.
///
/// Required names:
///   * cb `ClientboundCustomPayload`
///   * cb `ClientboundPing`
///   * cb `FinishConfiguration`
///   * sb `ServerboundCustomPayload`
///   * sb `AcknowledgeFinishConfiguration`
///
/// IDs verified from prismarine `data/pc/<ver>/protocol.json` (1.20.2 for
/// 764–765, 1.20.5 for 766+; 1.21+ shares the 766 layout).
#[rustfmt::skip]
const CONFIGURATION: &[Entry] = &[
    // 1.20.2 / 1.20.4 (proto 764 / 765 — 765 inherits via fallback).
    (764, ProtocolState::Configuration, Direction::Clientbound, "ClientboundCustomPayload",       0x00),
    (764, ProtocolState::Configuration, Direction::Clientbound, "ClientboundPluginMessage",       0x00),
    (764, ProtocolState::Configuration, Direction::Clientbound, "ClientboundDisconnect",          0x01),
    (764, ProtocolState::Configuration, Direction::Clientbound, "FinishConfiguration",            0x02),
    (764, ProtocolState::Configuration, Direction::Clientbound, "ClientboundKeepAlive",           0x03),
    (764, ProtocolState::Configuration, Direction::Clientbound, "ClientboundPing",                0x04),
    (764, ProtocolState::Configuration, Direction::Clientbound, "ClientboundRegistryData",        0x05),
    (764, ProtocolState::Configuration, Direction::Serverbound, "ServerboundCustomPayload",       0x01),
    (764, ProtocolState::Configuration, Direction::Serverbound, "ServerboundPluginMessage",       0x01),
    (764, ProtocolState::Configuration, Direction::Serverbound, "FinishConfiguration",            0x02),
    (764, ProtocolState::Configuration, Direction::Serverbound, "AcknowledgeFinishConfiguration", 0x02),

    // 1.20.5 / 1.20.6 (proto 766) — Cookie Request inserted at 0x00 shifts
    //   every clientbound id; serverbound got Cookie Response at 0x01 too.
    (766, ProtocolState::Configuration, Direction::Clientbound, "ClientboundCustomPayload",       0x01),
    (766, ProtocolState::Configuration, Direction::Clientbound, "ClientboundPluginMessage",       0x01),
    (766, ProtocolState::Configuration, Direction::Clientbound, "ClientboundDisconnect",          0x02),
    (766, ProtocolState::Configuration, Direction::Clientbound, "FinishConfiguration",            0x03),
    (766, ProtocolState::Configuration, Direction::Clientbound, "ClientboundKeepAlive",           0x04),
    (766, ProtocolState::Configuration, Direction::Clientbound, "ClientboundPing",                0x05),
    (766, ProtocolState::Configuration, Direction::Clientbound, "ClientboundRegistryData",        0x07),
    (766, ProtocolState::Configuration, Direction::Serverbound, "ServerboundCustomPayload",       0x02),
    (766, ProtocolState::Configuration, Direction::Serverbound, "ServerboundPluginMessage",       0x02),
    (766, ProtocolState::Configuration, Direction::Serverbound, "FinishConfiguration",            0x03),
    (766, ProtocolState::Configuration, Direction::Serverbound, "AcknowledgeFinishConfiguration", 0x03),
    // 1.21+ (767) configuration layout is identical to 766 — inherits via
    // fallback. 1.21.4 / 1.21.5 also unchanged for our subset.
];

/// Play state. Limited to the packet names actually looked up by the
/// proxy code (see `cb_play` / `sb_play` call sites in
/// `connection.rs`, `relay.rs`, `limbo.rs` and `packet_builder.rs`).
///
/// Required clientbound packets:
///   * `ClientboundJoinGame` / `ClientboundLogin` (modern alias, same id)
///   * `ClientboundRespawn`
///   * `ClientboundKeepAlive`
///   * `ClientboundChatMessage` (≤ 1.18.2) / `ClientboundSystemChat` (1.19+)
///   * `ClientboundPluginMessage` / `ClientboundCustomPayload` (alias)
///   * `ClientboundDisconnect`
///   * `ClientboundPlayerAbilities`
///   * `ClientboundPlayerPosition`
///   * `ClientboundSetCarriedItem` / `ClientboundSetHeldItem` (alias)
///   * `ClientboundSound` / `ClientboundNamedSoundEffect` (alias)
///   * `ClientboundBossBar`               (1.9+)
///   * `ClientboundLevelChunkWithLight`
///
/// Required serverbound packets:
///   * `ServerboundKeepAlive`
///   * `ServerboundChatMessage`
///   * `ServerboundChatCommand`           (1.19+)
///   * `ServerboundPluginMessage` / `ServerboundCustomPayload` (alias)
///
/// IDs verified against prismarine `data/pc/<ver>/protocol.json` for
/// each anchor below; sub-versions inherit via
/// `get_id_for_version`'s nearest-lower-proto fallback.
#[rustfmt::skip]
const PLAY: &[Entry] = &[
    //    Verified from minecraft.wiki Java_Edition_protocol_history#1.6.4.
    // Per HexaCord packet/ tree + MCP-doc class-name convention
    // `Packet<N><Name>` where N is the DECIMAL packet id, so hex id = N.
    // Previous values `0x13` and `0x43` were decimal `19` and `67`
    // misread as hex — the 1.6.4 Notchian client reported
    // "Bad packet id 67" when limbo emitted PlayerAbilities at 0x43
    // (no recognised 1.6.4 packet at that id). Corrected against
    // HexaCord packet classes:
    (78, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive",       0x00), // Packet0KeepAlive
    (78, ProtocolState::Play, Direction::Clientbound, "ClientboundLoginRequest",    0x01), // Packet1Login — the pre-netty "JoinGame"
    (78, ProtocolState::Play, Direction::Clientbound, "ClientboundTimeUpdate",      0x04), // Packet4UpdateTime
    (78, ProtocolState::Play, Direction::Clientbound, "ClientboundSpawnPosition",   0x06), // Packet6SpawnPosition
    (78, ProtocolState::Play, Direction::Clientbound, "ClientboundUpdateHealth",    0x08), // Packet8UpdateHealth
    (78, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage",     0x03), // Packet3Chat
    (78, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn",         0x09), // Packet9Respawn
    (78, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition",  0x0D), // Packet13PlayerLookMove (was 0x13)
    (78, ProtocolState::Play, Direction::Clientbound, "ClientboundHeldItemChange",  0x10), // Packet16BlockItemSwitch
    (78, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0xCA), // Packet202PlayerAbilities (was 0x43)
    (78, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect",      0xFF), // Packet255KickDisconnect

    //    Prismarine `1.7` is the closest equivalent. IDs verified there.
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x00),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x01),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x02),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x07),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x08),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x09),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x09),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x21),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x29),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x29),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x39),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x3F),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x3F),
    (5, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x40),
    (5, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x00),
    (5, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x01),
    (5, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x17),
    (5, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x17),
    (5, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerStatusOnly", 0x03),
    (5, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPos", 0x04),
    (5, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerRot", 0x05),
    (5, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPosRot", 0x06),

    // ── 1.8 (proto 47) — same shape as 1.7.10. BossBar still missing.
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x00),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x01),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x02),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x07),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x08),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x09),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x09),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x21),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x29),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x29),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x39),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x3F),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x3F),
    (47, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x40),
    (47, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x00),
    (47, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x01),
    (47, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x17),
    (47, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x17),
    (47, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerStatusOnly", 0x03),
    (47, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPos", 0x04),
    (47, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerRot", 0x05),
    (47, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPosRot", 0x06),

    // ── proto 107 (1.9) ──
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1f),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x23),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x23),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2b),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x2e),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x33),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x37),
    (107, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x37),
    (107, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (107, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x09),
    (107, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x09),
    (107, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0b),

    // ── proto 108 (1.9.1-pre2) ──
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1f),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x23),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x23),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2b),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x2e),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x33),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x37),
    (108, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x37),
    (108, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (108, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x09),
    (108, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x09),
    (108, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0b),

    // ── proto 109 (1.9.2) ──
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1f),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x23),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x23),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2b),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x2e),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x33),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x37),
    (109, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x37),
    (109, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (109, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x09),
    (109, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x09),
    (109, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0b),

    // ── proto 110 (1.9.4) ──
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1f),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x23),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x23),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2b),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x2e),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x33),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x37),
    (110, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x37),
    (110, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (110, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x09),
    (110, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x09),
    (110, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0b),

    // ── proto 210 (1.10) ──
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1f),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x23),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x23),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2b),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x2e),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x33),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x37),
    (210, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x37),
    (210, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (210, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x09),
    (210, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x09),
    (210, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0b),

    // ── proto 315 (1.11) ──
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1f),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x23),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x23),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2b),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x2e),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x33),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x37),
    (315, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x37),
    (315, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (315, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x09),
    (315, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x09),
    (315, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0b),

    // ── proto 316 (1.11) ──
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1F),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x23),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x23),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2b),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x2e),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x33),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x37),
    (316, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x37),
    (316, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (316, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x09),
    (316, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x09),
    (316, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0b),

    // ── proto 335 (1.12) ──
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0C),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1F),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x23),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x23),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2b),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x2e),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x34),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x39),
    (335, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x39),
    (335, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (335, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0a),
    (335, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0a),
    (335, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0c),

    // ── proto 338 (1.12.1) ──
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0C),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1F),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x23),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x23),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2c),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x2f),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x35),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3a),
    (338, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3a),
    (338, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (338, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x09),
    (338, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x09),
    (338, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0b),

    // ── proto 340 (1.12.2) ──
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0C),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1f),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x23),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x23),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2c),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x2f),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x35),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3a),
    (340, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3a),
    (340, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (340, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x09),
    (340, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x09),
    (340, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0b),
    (340, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerStatusOnly", 0x0c),
    (340, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPos", 0x0d),
    (340, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPosRot", 0x0e),
    (340, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerRot", 0x0f),

    // ── proto 393 (1.13) ──
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x19),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x19),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x1a),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x1a),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1b),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x21),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x22),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x25),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x25),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2e),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x32),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x38),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3d),
    (393, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3d),
    (393, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (393, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0a),
    (393, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0a),
    (393, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0e),

    // ── proto 401 (1.13.1) ──
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x19),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x19),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x1a),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x1a),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1b),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x21),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x22),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x25),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x25),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2e),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x32),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x38),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3d),
    (401, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3d),
    (401, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (401, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0a),
    (401, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0a),
    (401, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0e),

    // ── proto 404 (1.13.2) ──
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x19),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x19),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x1a),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x1a),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1b),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x21),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x22),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x25),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x25),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2e),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x32),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x38),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3d),
    (404, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3d),
    (404, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x02),
    (404, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0a),
    (404, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0a),
    (404, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0e),

    // ── proto 477 (1.14) ──
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x20),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x21),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x25),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x25),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x31),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x35),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3a),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3f),
    (477, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3f),
    (477, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (477, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (477, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (477, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 480 (1.14.1) ──
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x20),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x21),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x25),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x25),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x31),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x35),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3a),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3f),
    (480, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3f),
    (480, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (480, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (480, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (480, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 485 (1.14.1) ──
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x20),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x21),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x25),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x25),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x31),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x35),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3a),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3f),
    (485, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3f),
    (485, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (485, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (485, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (485, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 490 (1.14.3) ──
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x20),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x21),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x25),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x25),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x31),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x35),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3a),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3f),
    (490, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3f),
    (490, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (490, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (490, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (490, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 498 (1.14.4) ──
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x20),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x21),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x25),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x25),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x31),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x35),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3a),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3f),
    (498, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3f),
    (498, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (498, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (498, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (498, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 573 (1.15) ──
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0d),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x19),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x19),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x1a),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x1a),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1b),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x21),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x22),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x26),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x26),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x32),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x36),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3b),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x40),
    (573, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x40),
    (573, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (573, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (573, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (573, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 575 (1.15.1) ──
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0d),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x19),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x19),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x1a),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x1a),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1b),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x21),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x22),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x26),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x26),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x32),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x36),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3b),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x40),
    (575, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x40),
    (575, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (575, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (575, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (575, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 578 (1.15.2) ──
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0d),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x19),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x19),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x1a),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x1a),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1b),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x21),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x22),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x26),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x26),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x32),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x36),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3b),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x40),
    (578, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x40),
    (578, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (578, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (578, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (578, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 735 (1.16) ──
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x20),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x21),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x25),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x25),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x31),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x35),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3a),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3f),
    (735, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3f),
    (735, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (735, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (735, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (735, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x10),

    // ── proto 736 (1.16.1) ──
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x20),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x21),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x25),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x25),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x31),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x35),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3a),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3f),
    (736, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3f),
    (736, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (736, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (736, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (736, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x10),

    // ── proto 751 (1.16.2) ──
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x17),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x17),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x18),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x18),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x19),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1f),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x24),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x24),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x30),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x34),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x39),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3f),
    (751, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3f),
    (751, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (751, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (751, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (751, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x10),

    // ── proto 753 (1.16.2) ──
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x17),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x17),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x18),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x18),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x19),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1f),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x24),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x24),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x30),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x34),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x39),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3f),
    (753, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3f),
    (753, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (753, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (753, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (753, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x10),

    // ── proto 754 (1.16.2) ──
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0c),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0e),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x17),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x17),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x18),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x18),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x19),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1f),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x24),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x24),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x30),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x34),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x39),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x3f),
    (754, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x3f),
    (754, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (754, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0b),
    (754, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0b),
    (754, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x10),
    (754, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPos", 0x12),
    (754, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPosRot", 0x13),
    (754, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerRot", 0x14),
    (754, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerStatusOnly", 0x15),

    // ── proto 755 (1.17) ──
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0d),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x21),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x22),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x26),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x26),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x32),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x38),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3d),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x48),
    (755, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x48),
    (755, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (755, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0a),
    (755, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0a),
    (755, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 756 (1.17.1) ──
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0d),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x21),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x22),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x26),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x26),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x32),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x38),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3d),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x48),
    (756, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x48),
    (756, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (756, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0a),
    (756, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0a),
    (756, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 757 (1.18) ──
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0d),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x21),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x22),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x26),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x26),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x32),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x38),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3d),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x48),
    (757, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x48),
    (757, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (757, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0a),
    (757, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0a),
    (757, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 758 (1.18.2) ──
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0d),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundChatMessage", 0x0f),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x19),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x19),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x21),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x22),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x26),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x26),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x32),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x38),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3d),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x48),
    (758, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x48),
    (758, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x03),
    (758, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0a),
    (758, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0a),
    (758, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x0f),

    // ── proto 759 (1.19) ──
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0a),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x15),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x15),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x16),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x16),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x17),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1e),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x1f),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x23),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x23),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x2f),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x36),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3b),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x47),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x47),
    (759, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x5f),
    (759, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x03),
    (759, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x04),
    (759, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0c),
    (759, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0c),
    (759, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x11),

    // ── proto 760 (1.19.2) ──
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0a),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x16),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x16),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x17),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x17),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x19),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x20),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x21),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x25),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x25),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x31),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x39),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3e),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x4a),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x4a),
    (760, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x62),
    (760, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x04),
    (760, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x05),
    (760, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0d),
    (760, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0d),
    (760, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x12),

    // ── proto 761 (1.19.3) ──
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0a),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x15),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x15),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x17),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x1f),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x20),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x24),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x24),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x30),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x38),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x3d),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x49),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x49),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x5e),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x5e),
    (761, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x60),
    (761, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x04),
    (761, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x05),
    (761, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0c),
    (761, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0c),
    (761, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x11),

    // ── proto 762 (1.19.4) ──
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0b),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x17),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x17),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x23),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x24),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x28),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x28),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x34),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x3c),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x41),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x4d),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x4d),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x62),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x62),
    (762, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x64),
    (762, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x04),
    (762, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x05),
    (762, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0d),
    (762, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0d),
    (762, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x12),
    (762, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPos", 0x14),
    (762, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPosRot", 0x15),
    (762, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerRot", 0x16),
    (762, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerStatusOnly", 0x17),

    // ── proto 763 (1.20) ──
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0b),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x17),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x17),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1a),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x23),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x24),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x28),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x28),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x34),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x3c),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x41),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x4d),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x4d),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x62),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x62),
    (763, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x64),
    (763, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x04),
    (763, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x05),
    (763, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0d),
    (763, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0d),
    (763, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x12),

    // ── proto 764 (1.20.2) ──
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0a),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1b),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x24),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x25),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x29),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x29),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x36),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x3e),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x43),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x4f),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x4f),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x64),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x64),
    (764, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x67),
    (764, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x04),
    (764, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x05),
    (764, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0f),
    (764, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0f),
    (764, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x14),

    // ── proto 765 (1.20.4 — `MINECRAFT_1_20_3` in BungeeCord naming) ──
    // Comment in source previously said "1.20.2"; proto 765 is actually
    // 1.20.4 (1.20.2 is proto 764). Per BungeeCord `Protocol.java`,
    // many IDs shift by +1 between 764 and 765 — corrected below.
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0a),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1b),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x24),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x25),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x29),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x29),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x36),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x3e),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x43),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x4f),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x4f),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x64),
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x64),
    // Per BungeeCord `Protocol.java::TO_CLIENT` SystemChat table:
    //   `map(MINECRAFT_1_20_2, 0x67)` then `map(MINECRAFT_1_20_3, 0x69)`.
    // Proto 765 (1.20.4 = `MINECRAFT_1_20_3` in BungeeCord) → 0x69. The
    // previous 0x67 was the 1.20.2 value.
    (765, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x69),
    (765, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x04),
    (765, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x05),
    (765, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x0f),
    (765, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x0f),
    // KeepAlive c2s shifts +1 between 1.20.2 (0x14) and 1.20.3/1.20.4 (0x15).
    // Per BungeeCord `Protocol.java` TO_SERVER table for the KeepAlive packet.
    (765, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x15),
    (765, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPos", 0x16),
    (765, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPosRot", 0x17),
    (765, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerRot", 0x18),
    (765, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerStatusOnly", 0x19),

    // ── proto 766 (1.20.5) ──
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0a),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x19),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x19),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1d),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x26),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x27),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x2b),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x2b),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x38),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x40),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x47),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x53),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x53),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x68),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x68),
    (766, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x6c),
    (766, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x04),
    (766, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x06),
    (766, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x12),
    (766, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x12),
    (766, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x18),

    // ── proto 767 (1.21.1) ──
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0a),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x19),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x19),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1d),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x26),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x27),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x2b),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x2b),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x38),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x40),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x47),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x53),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x53),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x68),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x68),
    (767, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x6c),
    (767, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x04),
    (767, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x06),
    (767, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x12),
    (767, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x12),
    (767, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x18),
    (767, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPos", 0x1a),
    (767, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPosRot", 0x1b),
    (767, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerRot", 0x1c),
    (767, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerStatusOnly", 0x1d),

    // ── proto 768 (1.21.3) ──
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0a),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x19),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x19),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1d),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x27),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x28),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x2c),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x2c),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x3a),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x42),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x4c),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x63),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x63),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x6f),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x6f),
    (768, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x73),
    (768, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x05),
    (768, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x07),
    (768, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x14),
    (768, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x14),
    (768, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x1a),

    // ── proto 769 (1.21.4) ──
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x0a),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x19),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x19),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1d),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x27),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x28),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x2c),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x2c),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x3a),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x42),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x4c),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x63),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x63),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x6f),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x6f),
    (769, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x73),
    (769, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x05),
    (769, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x07),
    (769, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x14),
    (769, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x14),
    (769, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x1a),
    (769, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPos", 0x1c),
    (769, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPosRot", 0x1d),
    (769, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerRot", 0x1e),
    (769, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerStatusOnly", 0x1f),

    // ── proto 770 (1.21.5) ──
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x09),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1c),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x26),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x27),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x2b),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x2b),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x39),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x41),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x4b),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x62),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x62),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x6e),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x6e),
    (770, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x72),
    (770, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x05),
    (770, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x07),
    (770, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x14),
    (770, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x14),
    (770, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x1a),
    (770, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPos", 0x1c),
    (770, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerPosRot", 0x1d),
    (770, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerRot", 0x1e),
    (770, ProtocolState::Play, Direction::Serverbound, "ServerboundMovePlayerStatusOnly", 0x1f),

    // ── proto 771 (1.21.6) — same as 770; explicit for clarity.
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x09),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1c),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x26),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x27),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x2b),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x2b),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x39),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x41),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x4b),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x62),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x62),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x6e),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x6e),
    (771, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x72),
    (771, ProtocolState::Play, Direction::Serverbound, "ServerboundChatCommand", 0x05),
    (771, ProtocolState::Play, Direction::Serverbound, "ServerboundChatMessage", 0x07),
    (771, ProtocolState::Play, Direction::Serverbound, "ServerboundPluginMessage", 0x14),
    (771, ProtocolState::Play, Direction::Serverbound, "ServerboundCustomPayload", 0x14),
    (771, ProtocolState::Play, Direction::Serverbound, "ServerboundKeepAlive", 0x1a),

    // ── proto 772 (1.21.8) — verified from prismarine 1.21.8 (same as 1.21.6).
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x09),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x1c),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x26),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x27),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x2b),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x2b),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x39),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x41),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x4b),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x62),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x62),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x6e),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x6e),
    (772, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x72),

    // ── proto 773 (1.21.9) — significant renumber.
    //    Verified from prismarine `1.21.9`.
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x09),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x20),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x2b),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x2c),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x30),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x30),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x3e),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x46),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x50),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x67),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x67),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x73),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x73),
    (773, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x77),

    // ── proto 774 (1.21.11) — same as 1.21.9 (no further renumber).
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundBossBar", 0x09),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundPluginMessage", 0x18),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundCustomPayload", 0x18),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundDisconnect", 0x20),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundKeepAlive", 0x2b),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundLevelChunkWithLight", 0x2c),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundJoinGame", 0x30),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundLogin", 0x30),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerAbilities", 0x3e),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundPlayerPosition", 0x46),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundRespawn", 0x50),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundSetHeldItem", 0x67),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundSetCarriedItem", 0x67),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundSound", 0x73),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundNamedSoundEffect", 0x73),
    (774, ProtocolState::Play, Direction::Clientbound, "ClientboundSystemChat", 0x77),
];

const ALL_TABLES: &[&[Entry]] = &[PRE_NETTY, HANDSHAKE, STATUS, LOGIN, CONFIGURATION, PLAY];

pub fn build_default_registry() -> PacketRegistry {
    let mut r = PacketRegistry::new();
    for table in ALL_TABLES {
        for &(proto, state, dir, name, id) in *table {
            r.register(proto, state, dir, name, id);
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_v1_12_2_is_0x1f() {
        let r = build_default_registry();
        // 1.12.2 (proto 340) inherits from 1.9 (107) via nearest-lookup —
        // 1.12 (335) didn't change KeepAlive id. Confirms the long-standing
        // 0x00 bug is gone.
        assert_eq!(
            r.get_id_for_version(
                340,
                ProtocolState::Play,
                Direction::Clientbound,
                "ClientboundKeepAlive"
            ),
            Some(0x1F)
        );
    }

    #[test]
    fn play_disconnect_v1_12_2_is_0x1a() {
        let r = build_default_registry();
        assert_eq!(
            r.get_id_for_version(
                340,
                ProtocolState::Play,
                Direction::Clientbound,
                "ClientboundDisconnect"
            ),
            Some(0x1A)
        );
    }

    #[test]
    fn finish_configuration_v1_20_4_is_0x02() {
        let r = build_default_registry();
        assert_eq!(
            r.get_id_for_version(
                765,
                ProtocolState::Configuration,
                Direction::Clientbound,
                "FinishConfiguration"
            ),
            Some(0x02)
        );
    }

    #[test]
    fn subversion_fallback_works() {
        let r = build_default_registry();
        // 1.12 (335) is its own anchor — JoinGame 0x23.
        assert_eq!(
            r.get_id_for_version(
                335,
                ProtocolState::Play,
                Direction::Clientbound,
                "ClientboundJoinGame"
            ),
            Some(0x23)
        );
        // 1.10.x (210) inherits from the 1.9.4 (110) anchor.
        assert_eq!(
            r.get_id_for_version(
                210,
                ProtocolState::Play,
                Direction::Clientbound,
                "ClientboundJoinGame"
            ),
            Some(0x23)
        );
        // 1.16.5 (754) is the anchor itself.
        assert_eq!(
            r.get_id_for_version(
                754,
                ProtocolState::Play,
                Direction::Clientbound,
                "ClientboundJoinGame"
            ),
            Some(0x24)
        );
        // 1.21.4 (769) is its own anchor.
        assert_eq!(
            r.get_id_for_version(
                769,
                ProtocolState::Play,
                Direction::Clientbound,
                "ClientboundSystemChat"
            ),
            Some(0x73)
        );
        // 1.21.5 (770) is its own anchor.
        assert_eq!(
            r.get_id_for_version(
                770,
                ProtocolState::Play,
                Direction::Clientbound,
                "ClientboundSystemChat"
            ),
            Some(0x72)
        );
    }

    #[test]
    fn login_success_stable_across_eras() {
        let r = build_default_registry();
        for proto in [5, 47, 340, 393, 762, 765, 767] {
            assert_eq!(
                r.get_id_for_version(
                    proto,
                    ProtocolState::Login,
                    Direction::Clientbound,
                    "ClientboundLoginSuccess"
                ),
                Some(0x02),
                "LoginSuccess should be 0x02 for proto {proto}"
            );
        }
    }

    #[test]
    fn login_acknowledged_only_1_20_2_plus() {
        let r = build_default_registry();
        assert_eq!(
            r.get_id_for_version(
                762,
                ProtocolState::Login,
                Direction::Serverbound,
                "ServerboundLoginAcknowledged"
            ),
            None,
            "1.19.4 has no LoginAcknowledged"
        );
        assert_eq!(
            r.get_id_for_version(
                765,
                ProtocolState::Login,
                Direction::Serverbound,
                "ServerboundLoginAcknowledged"
            ),
            Some(0x03)
        );
    }

    /// Every supported sub-version (1.9.x ... 1.21.x) must resolve a
    /// `ClientboundJoinGame`/`ClientboundLogin` id from the registry —
    /// proves the wiring is in place for every protocol family the user
    /// asked for.
    #[test]
    fn every_subversion_resolves_join_game() {
        for proto in [
            // 1.9.x
            107, 108, 109, 110, // 1.10
            210, // 1.11.x
            315, 316, // 1.12.x
            335, 338, 340, // 1.13.x
            393, 401, 404, // 1.14.x
            477, 480, 485, 490, 498, // 1.15.x
            573, 575, 578, // 1.16.x
            735, 736, 751, 753, 754, // 1.17.x
            755, 756, // 1.18.x
            757, 758, // 1.19.x
            759, 760, 761, 762, // 1.20.x
            763, 764, 765, 766, // 1.21.x
            767, 768, 769, 770, 771, 772, 773, 774,
        ] {
            // 1.9 through 1.18.2 register under `ClientboundJoinGame`;
            // 1.19+ adds `ClientboundLogin` as an alias for the same id.
            let name = if proto >= 759 {
                "ClientboundLogin"
            } else {
                "ClientboundJoinGame"
            };
            let id = cb_play(proto, name);
            assert_ne!(
                id, 0xFF,
                "proto {} ({}) failed to resolve in the registry — wiring is broken",
                proto, name
            );
        }
    }
}
