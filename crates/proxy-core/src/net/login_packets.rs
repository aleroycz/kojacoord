//! Login + handshake packet builders, keyed by canonical version.
//!
//! Mirrors [`crate::limbo_packets`] but covers the smaller surface
//! `connection.rs` needs around the login/handshake dance:
//!   * Server-issued: LoginSuccess, EncryptionRequest, LoginDisconnect,
//!     SetCompression, PlayDisconnect
//!   * Backend-bound: Handshake, ServerboundLoginStart
//!
//! Each builder returns `(packet_id, body)` as an [`EncodedPacket`].
//! `None` means "this canonical bucket doesn't speak that packet"
//! (e.g. pre-netty has its own LoginRequestS2C shape that's handled
//! separately).
//!
//! The pattern: every site in `connection.rs` that used to inline a
//! 7-arm match by `CanonicalVersion` is collapsed into a single
//! builder call here, keeping connection.rs streamlined and the
//! per-version typed-packet imports localised in this file.

use bytes::BytesMut;
use kojacoord_protocol::{
    codec::{Encode, PacketId},
    CanonicalVersion,
};
use uuid::Uuid;

pub struct EncodedPacket {
    pub id: u8,
    pub body: BytesMut,
}

/// Encode a typed login packet (`id` + `body`). Returns `None` when
/// the proto sentinel says this packet doesn't exist for that
/// version.
fn encode<T: Encode + PacketId>(proto: u32, pkt: T) -> Option<EncodedPacket> {
    let id = T::packet_id(proto);
    if id == 0xFF {
        return None;
    }
    let mut body = BytesMut::new();
    pkt.encode(&mut body).ok()?;
    Some(EncodedPacket { id, body })
}

/// Profile properties as the caller knows them (auth crate type).
/// Each impl converts these into its own typed `ProfileProperty`
/// before encoding.
pub struct LoginProfile<'a> {
    pub uuid: Uuid,
    pub username: &'a str,
    pub properties: &'a [kojacoord_auth::ProfileProperty],
}

/// Build a clientbound LoginSuccess packet for the given canonical
/// bucket. Returns `None` only for pre-netty (1.6.x) — call sites that
/// support 1.6 must use the alternate `LoginRequestS2C` path.
pub fn build_login_success(
    canonical: CanonicalVersion,
    proto: u32,
    profile: &LoginProfile<'_>,
) -> Option<EncodedPacket> {
    let uuid = profile.uuid;
    let username = profile.username.to_owned();
    match canonical {
        CanonicalVersion::V1_6_4 => None,
        CanonicalVersion::V1_7_10 => {
            use kojacoord_protocol::versions::v1_7_x::login::ClientboundLoginSuccess;
            encode(proto, ClientboundLoginSuccess { uuid, username })
        },
        CanonicalVersion::V1_8 => {
            use kojacoord_protocol::versions::v1_8_x::login::ClientboundLoginSuccess;
            encode(proto, ClientboundLoginSuccess { uuid, username })
        },
        CanonicalVersion::V1_12_2 => {
            use kojacoord_protocol::versions::v1_12_x::login::{
                ClientboundLoginSuccess, ProfileProperty,
            };
            encode(
                proto,
                ClientboundLoginSuccess {
                    uuid,
                    username,
                    properties: profile
                        .properties
                        .iter()
                        .map(|p| ProfileProperty {
                            name: p.name.clone(),
                            value: p.value.clone(),
                            signature: p.signature.clone(),
                        })
                        .collect(),
                },
            )
        },
        CanonicalVersion::V1_16_5 => {
            // LoginSuccess wire shape:
            //   proto 5  - 578  (1.7  - 1.15.2): String UUID (hyphenated,
            //                                   client-side capped at 36) +
            //                                   String username (capped at 16).
            //   proto 735+ (1.16+)              : 16 raw UUID bytes +
            //                                   String username (+ properties
            //                                   from 1.19 onward).
            //
            // The V1_16_5 canonical bucket spans the whole 1.13 - 1.16
            // epoch on the play side (it owns the flattened block table,
            // dimension codec, etc.) but the login-state UUID shape
            // changed at proto 735. So we dispatch on proto here instead
            // of canonical: anything before 735 borrows the v1_12 typed
            // packet (UUID-as-string), 735+ uses the v1_16 form.
            //
            // Without this branch a 1.13-1.15 client reads the first
            // byte of our 16-byte UUID as a VarInt String length —
            // common values land in the 100s — and disconnects with
            // "The received string length is longer than maximum
            // allowed (NNN > 36)". Confirmed against minecraft.wiki
            // Java_Edition_protocol/Packets#Login_Success.
            if proto < 735 {
                use kojacoord_protocol::versions::v1_12_x::login::ClientboundLoginSuccess;
                encode(
                    proto,
                    ClientboundLoginSuccess {
                        uuid,
                        username,
                        properties: Vec::new(),
                    },
                )
            } else {
                use kojacoord_protocol::versions::v1_16_x::login::{
                    ClientboundLoginSuccess, ProfileProperty,
                };
                encode(
                    proto,
                    ClientboundLoginSuccess {
                        uuid,
                        username,
                        properties: profile
                            .properties
                            .iter()
                            .map(|p| ProfileProperty {
                                name: p.name.clone(),
                                value: p.value.clone(),
                                signature: p.signature.clone(),
                            })
                            .collect(),
                    },
                )
            }
        },
        CanonicalVersion::V1_19_4 => {
            use kojacoord_protocol::versions::v1_19_x::login::{
                ClientboundLoginSuccess, ProfileProperty,
            };
            encode(
                proto,
                ClientboundLoginSuccess {
                    uuid,
                    username,
                    properties: profile
                        .properties
                        .iter()
                        .map(|p| ProfileProperty {
                            name: p.name.clone(),
                            value: p.value.clone(),
                            signature: p.signature.clone(),
                        })
                        .collect(),
                },
            )
        },
        CanonicalVersion::V1_20_4 => {
            use kojacoord_protocol::versions::v1_20_x::login::{
                ClientboundLoginSuccess, ProfileProperty,
            };
            // `strictErrorHandling` lives on the wire for 1.20.5+ (proto 766).
            // For 1.20.0–1.20.4 the trailing byte must be absent.
            let strict = if proto >= 766 { Some(true) } else { None };
            encode(
                proto,
                ClientboundLoginSuccess {
                    uuid,
                    username,
                    properties: profile
                        .properties
                        .iter()
                        .map(|p| ProfileProperty {
                            name: p.name.clone(),
                            value: p.value.clone(),
                            signature: p.signature.clone(),
                        })
                        .collect(),
                    strict_error_handling: strict,
                },
            )
        },
        CanonicalVersion::V1_21 => {
            use kojacoord_protocol::versions::v1_21_x::login::{
                ClientboundLoginSuccess, ProfileProperty,
            };
            // 1.21 (767) and 1.21.2 (768) carry strictErrorHandling.
            // 1.21.4+ (769+) dropped it again.
            let strict = if (767..=768).contains(&proto) {
                Some(true)
            } else {
                None
            };
            encode(
                proto,
                ClientboundLoginSuccess {
                    uuid,
                    username,
                    properties: profile
                        .properties
                        .iter()
                        .map(|p| ProfileProperty {
                            name: p.name.clone(),
                            value: p.value.clone(),
                            signature: p.signature.clone(),
                        })
                        .collect(),
                    strict_error_handling: strict,
                },
            )
        },
    }
}

/// Build a clientbound EncryptionRequest packet.
/// `proto` controls whether `should_authenticate` is serialised
/// (1.20.5+).
pub fn build_encryption_request(
    canonical: CanonicalVersion,
    proto: u32,
    server_id: &str,
    public_key: &[u8],
    verify_token: &[u8],
) -> Option<EncodedPacket> {
    let server_id = server_id.to_owned();
    let public_key = public_key.to_vec();
    let verify_token = verify_token.to_vec();
    match canonical {
        CanonicalVersion::V1_6_4 => None,
        CanonicalVersion::V1_7_10 => {
            use kojacoord_protocol::versions::v1_7_x::login::ClientboundEncryptionRequest;
            encode(
                proto,
                ClientboundEncryptionRequest {
                    server_id,
                    public_key,
                    verify_token,
                },
            )
        },
        CanonicalVersion::V1_8 => {
            use kojacoord_protocol::versions::v1_8_x::login::ClientboundEncryptionRequest;
            encode(
                proto,
                ClientboundEncryptionRequest {
                    server_id,
                    public_key,
                    verify_token,
                },
            )
        },
        CanonicalVersion::V1_12_2 => {
            use kojacoord_protocol::versions::v1_12_x::login::ClientboundEncryptionRequest;
            encode(
                proto,
                ClientboundEncryptionRequest {
                    server_id,
                    public_key,
                    verify_token,
                },
            )
        },
        CanonicalVersion::V1_16_5 => {
            use kojacoord_protocol::versions::v1_16_x::login::ClientboundEncryptionRequest;
            encode(
                proto,
                ClientboundEncryptionRequest {
                    server_id,
                    public_key,
                    verify_token,
                },
            )
        },
        CanonicalVersion::V1_19_4 => {
            use kojacoord_protocol::versions::v1_19_x::login::ClientboundEncryptionRequest;
            encode(
                proto,
                ClientboundEncryptionRequest {
                    server_id,
                    public_key,
                    verify_token,
                },
            )
        },
        CanonicalVersion::V1_20_4 => {
            use kojacoord_protocol::versions::v1_20_x::login::ClientboundEncryptionRequest;
            // 1.20.5+ added the `should_authenticate` boolean.
            let auth = if proto >= 766 { Some(true) } else { None };
            encode(
                proto,
                ClientboundEncryptionRequest {
                    server_id,
                    public_key,
                    verify_token,
                    should_authenticate: auth,
                },
            )
        },
        CanonicalVersion::V1_21 => {
            use kojacoord_protocol::versions::v1_21_x::login::ClientboundEncryptionRequest;
            encode(
                proto,
                ClientboundEncryptionRequest {
                    server_id,
                    public_key,
                    verify_token,
                    should_authenticate: Some(true),
                },
            )
        },
    }
}

/// Build a clientbound SetCompression packet for the given canonical
/// bucket. Returns `None` for pre-netty (1.6.x) and 1.7.x — neither
/// epoch speaks SetCompression. Per
/// <https://minecraft.wiki/w/Java_Edition_protocol/Packets> the packet
/// was introduced in 1.8 (protocol 47).
///
/// Same builder pattern as `build_login_success` /
/// `build_encryption_request`: each typed `ClientboundSetCompression`
/// across the per-version modules has an identical shape (single
/// `threshold: VarInt`), so the per-arm code reduces to picking the
/// correct typed import. The bridge here keeps `connection.rs`
/// single-call for all six canonical buckets, matching the
/// LoginSuccess / EncryptionRequest / LoginDisconnect pattern.
pub fn build_set_compression(
    canonical: CanonicalVersion,
    proto: u32,
    threshold: i32,
) -> Option<EncodedPacket> {
    use kojacoord_protocol::types::VarInt;
    match canonical {
        CanonicalVersion::V1_6_4 => None,
        CanonicalVersion::V1_7_10 => None,
        CanonicalVersion::V1_8 => {
            use kojacoord_protocol::versions::v1_8_x::login::ClientboundSetCompression;
            encode(
                proto,
                ClientboundSetCompression {
                    threshold: VarInt(threshold),
                },
            )
        },
        CanonicalVersion::V1_12_2 => {
            use kojacoord_protocol::versions::v1_12_x::login::ClientboundSetCompression;
            encode(
                proto,
                ClientboundSetCompression {
                    threshold: VarInt(threshold),
                },
            )
        },
        CanonicalVersion::V1_16_5 => {
            use kojacoord_protocol::versions::v1_16_x::login::ClientboundSetCompression;
            encode(
                proto,
                ClientboundSetCompression {
                    threshold: VarInt(threshold),
                },
            )
        },
        CanonicalVersion::V1_19_4 => {
            use kojacoord_protocol::versions::v1_19_x::login::ClientboundSetCompression;
            encode(
                proto,
                ClientboundSetCompression {
                    threshold: VarInt(threshold),
                },
            )
        },
        CanonicalVersion::V1_20_4 => {
            use kojacoord_protocol::versions::v1_20_x::login::ClientboundSetCompression;
            encode(
                proto,
                ClientboundSetCompression {
                    threshold: VarInt(threshold),
                },
            )
        },
        CanonicalVersion::V1_21 => {
            use kojacoord_protocol::versions::v1_21_x::login::ClientboundSetCompression;
            encode(
                proto,
                ClientboundSetCompression {
                    threshold: VarInt(threshold),
                },
            )
        },
    }
}

/// Build a clientbound LoginDisconnect packet. Pre-netty (1.6.x) uses
/// a different framing — callers handle that separately and only call
/// this for 1.7+.
pub fn build_login_disconnect(
    canonical: CanonicalVersion,
    proto: u32,
    reason_json: &str,
) -> Option<EncodedPacket> {
    let reason = reason_json.to_owned();
    match canonical {
        CanonicalVersion::V1_6_4 => None,
        CanonicalVersion::V1_7_10 => {
            use kojacoord_protocol::versions::v1_7_x::login::ClientboundLoginDisconnect;
            encode(proto, ClientboundLoginDisconnect { reason })
        },
        CanonicalVersion::V1_8 => {
            use kojacoord_protocol::versions::v1_8_x::login::ClientboundLoginDisconnect;
            encode(proto, ClientboundLoginDisconnect { reason })
        },
        CanonicalVersion::V1_12_2 => {
            use kojacoord_protocol::versions::v1_12_x::login::ClientboundLoginDisconnect;
            encode(proto, ClientboundLoginDisconnect { reason })
        },
        CanonicalVersion::V1_16_5 => {
            use kojacoord_protocol::versions::v1_16_x::login::ClientboundLoginDisconnect;
            encode(proto, ClientboundLoginDisconnect { reason })
        },
        CanonicalVersion::V1_19_4 => {
            use kojacoord_protocol::versions::v1_19_x::login::ClientboundLoginDisconnect;
            encode(proto, ClientboundLoginDisconnect { reason })
        },
        CanonicalVersion::V1_20_4 => {
            use kojacoord_protocol::versions::v1_20_x::login::ClientboundLoginDisconnect;
            encode(proto, ClientboundLoginDisconnect { reason })
        },
        CanonicalVersion::V1_21 => {
            use kojacoord_protocol::versions::v1_21_x::login::ClientboundLoginDisconnect;
            encode(proto, ClientboundLoginDisconnect { reason })
        },
    }
}

/// Build a clientbound Play-state Disconnect packet for the given
/// canonical bucket. Each version uses its own typed `ClientboundDisconnect`
/// (single `reason: String` field). Returns `None` only if the version
/// somehow lacks a play-state Disconnect (none do today, but the option
/// keeps the signature symmetric with the other builders).
pub fn build_play_disconnect(
    canonical: CanonicalVersion,
    proto: u32,
    reason_json: &str,
) -> Option<EncodedPacket> {
    let reason = reason_json.to_owned();
    match canonical {
        CanonicalVersion::V1_6_4 => {
            use kojacoord_protocol::versions::v1_6_x::play::ClientboundDisconnect;
            encode(proto, ClientboundDisconnect { reason })
        },
        CanonicalVersion::V1_7_10 => {
            use kojacoord_protocol::versions::v1_7_x::play::ClientboundDisconnect;
            encode(proto, ClientboundDisconnect { reason })
        },
        CanonicalVersion::V1_8 => {
            use kojacoord_protocol::versions::v1_8_x::play::ClientboundDisconnect;
            encode(proto, ClientboundDisconnect { reason })
        },
        CanonicalVersion::V1_12_2 => {
            use kojacoord_protocol::versions::v1_12_x::play::ClientboundDisconnect;
            encode(proto, ClientboundDisconnect { reason })
        },
        CanonicalVersion::V1_16_5 => {
            use kojacoord_protocol::versions::v1_16_x::play::ClientboundDisconnect;
            encode(proto, ClientboundDisconnect { reason })
        },
        CanonicalVersion::V1_19_4 => {
            use kojacoord_protocol::versions::v1_19_x::play::ClientboundDisconnect;
            encode(proto, ClientboundDisconnect { reason })
        },
        CanonicalVersion::V1_20_4 => {
            use kojacoord_protocol::versions::v1_20_x::play::ClientboundDisconnect;
            encode(proto, ClientboundDisconnect { reason })
        },
        CanonicalVersion::V1_21 => {
            use kojacoord_protocol::versions::v1_21_x::play::ClientboundDisconnect;
            encode(proto, ClientboundDisconnect { reason })
        },
    }
}

/// Build a serverbound Handshake packet for relaying to a backend.
/// `next_state = 2` for login (the only state this proxy initiates
/// toward backends). Pre-netty (V1_6_4) is intentionally absent — the
/// backend handshake path always speaks netty since the proxy itself
/// is netty-only. Returns the modern `ServerboundHandshake` (VarInt
/// proto + String addr + u16 port + VarInt state) for every netty
/// canonical bucket.
pub fn build_backend_handshake(
    canonical: CanonicalVersion,
    proto: u32,
    server_address: String,
    server_port: u16,
) -> Option<EncodedPacket> {
    use kojacoord_protocol::types::VarInt;
    if matches!(canonical, CanonicalVersion::V1_6_4) {
        return None;
    }
    // All netty buckets share the same modern handshake shape; pick the
    // v1_8_x typed packet as canonical.
    use kojacoord_protocol::versions::v1_8_x::handshake::ServerboundHandshake;
    encode(
        proto,
        ServerboundHandshake {
            protocol_version: VarInt(proto as i32),
            server_address,
            server_port,
            next_state: VarInt(2),
        },
    )
}

/// Decode and discard a clientbound LoginSuccess body from a Bytes
/// cursor. Used by `complete_backend_login` purely to advance the
/// cursor past the LoginSuccess payload before reading the next
/// packet — we don't care about its fields because we issued the
/// LoginSuccess to the client ourselves on the other side.
///
/// Each canonical bucket uses its own typed `ClientboundLoginSuccess`
/// shape (1.7 uses UUID-as-string; 1.12+ uses UUID-bytes; 1.19+ adds
/// properties; 1.20.5/1.21 may add strict-error-handling). Centralising
/// it here keeps the per-version typed-packet imports out of
/// connection.rs.
pub fn skip_backend_login_success(canonical: CanonicalVersion, cursor: &mut bytes::Bytes) {
    use kojacoord_protocol::codec::Decode;
    match canonical {
        CanonicalVersion::V1_6_4 | CanonicalVersion::V1_7_10 => {
            use kojacoord_protocol::versions::v1_7_x::login::ClientboundLoginSuccess;
            let _ = ClientboundLoginSuccess::decode(cursor);
        },
        CanonicalVersion::V1_8 => {
            use kojacoord_protocol::versions::v1_8_x::login::ClientboundLoginSuccess;
            let _ = ClientboundLoginSuccess::decode(cursor);
        },
        CanonicalVersion::V1_12_2 => {
            use kojacoord_protocol::versions::v1_12_x::login::ClientboundLoginSuccess;
            let _ = ClientboundLoginSuccess::decode(cursor);
        },
        CanonicalVersion::V1_16_5 => {
            use kojacoord_protocol::versions::v1_16_x::login::ClientboundLoginSuccess;
            let _ = ClientboundLoginSuccess::decode(cursor);
        },
        CanonicalVersion::V1_19_4 => {
            use kojacoord_protocol::versions::v1_19_x::login::ClientboundLoginSuccess;
            let _ = ClientboundLoginSuccess::decode(cursor);
        },
        CanonicalVersion::V1_20_4 => {
            use kojacoord_protocol::versions::v1_20_x::login::ClientboundLoginSuccess;
            let _ = ClientboundLoginSuccess::decode(cursor);
        },
        CanonicalVersion::V1_21 => {
            use kojacoord_protocol::versions::v1_21_x::login::ClientboundLoginSuccess;
            let _ = ClientboundLoginSuccess::decode(cursor);
        },
    }
}

/// Build a serverbound LoginStart packet to relay to a backend.
/// Handles the three field shapes per minecraft.wiki Login_Start:
///   * 1.8 / 1.12.2 / 1.16.5 (proto 47 — 758): username
///   * 1.19.x — 1.20.1 (proto 759 — 763): username + Option<UUID>
///   * 1.20.2+ (proto 764+): username + mandatory UUID
///
/// `uuid` is what the proxy will tell the backend the player is. Pre-
/// netty isn't supported (V1_6_4 returns `None`) — pre-netty login
/// has its own 0x02 Handshake-with-username shape, not LoginStart.
pub fn build_backend_login_start(
    canonical: CanonicalVersion,
    proto: u32,
    username: String,
    uuid: Uuid,
) -> Option<EncodedPacket> {
    // 1.19.x: Option<UUID>. Also 1.20.0/1.20.1 (proto 763) which the
    // CanonicalVersion::V1_20_4 bucket covers up to but not including 764.
    if matches!(canonical, CanonicalVersion::V1_19_4)
        || (canonical == CanonicalVersion::V1_20_4 && proto < 764)
    {
        use kojacoord_protocol::versions::v1_19_x::login::ServerboundLoginStart;
        return encode(
            proto,
            ServerboundLoginStart {
                username,
                uuid: Some(uuid),
            },
        );
    }
    // 1.20.2+ (proto 764+) including 1.21: mandatory UUID.
    if matches!(
        canonical,
        CanonicalVersion::V1_20_4 | CanonicalVersion::V1_21
    ) {
        use kojacoord_protocol::versions::v1_20_x::login::ServerboundLoginStart;
        return encode(proto, ServerboundLoginStart { username, uuid });
    }
    // 1.16.5: username only (no UUID yet).
    if matches!(canonical, CanonicalVersion::V1_16_5) {
        use kojacoord_protocol::versions::v1_16_x::login::ServerboundLoginStart;
        return encode(proto, ServerboundLoginStart { username });
    }
    // 1.8 / 1.12.2 / 1.7.10: username only.
    if matches!(
        canonical,
        CanonicalVersion::V1_7_10 | CanonicalVersion::V1_8 | CanonicalVersion::V1_12_2
    ) {
        use kojacoord_protocol::versions::v1_8_x::login::ServerboundLoginStart;
        return encode(proto, ServerboundLoginStart { username });
    }
    // V1_6_4: no LoginStart packet (pre-netty has Handshake-with-username).
    None
}
