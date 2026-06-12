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
            // LoginSuccess wire shape — three distinct era boundaries
            // inside this canonical bucket. Verified against
            // minecraft.wiki Java_Edition_protocol/Packets#Login_Success
            // per-version entries:
            //
            //   proto 5 - 578  (1.7 - 1.15.2):
            //       String UUID (hyphenated, client-side capped at 36)
            //       String username (capped at 16)
            //
            //   proto 735 - 758 (1.16 - 1.18.2):
            //       16 raw UUID bytes
            //       String username
            //       (NO properties array — added later)
            //
            //   proto 759+ (1.19+):
            //       16 raw UUID bytes
            //       String username
            //       VarInt prop_count + N × ProfileProperty
            //
            // The previous code lumped 1.16+ together using the v1_16
            // typed struct, which unconditionally writes the prop_count
            // VarInt + properties — but for an online-mode player with
            // a real Mojang `textures` property attached, that's ~1000
            // bytes the 1.16-1.18 client sees as trailing garbage and
            // rejects with
            // `"Packet 2/2 (sy) was larger than I expected, found NNNN
            // bytes extra whilst reading packet 2"`.
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
            } else if proto < 759 {
                // 1.16 - 1.18: raw UUID + String username, no
                // properties trailer. Hand-encode rather than
                // borrowing a typed struct, since neither v1_16 nor
                // v1_19 typed forms match this exact shape (v1_16
                // includes properties; v1_19 also includes properties).
                use kojacoord_protocol::codec::Encode;
                use kojacoord_protocol::types::VarInt;
                let mut body = bytes::BytesMut::new();
                let (hi, lo) = uuid.as_u64_pair();
                use bytes::BufMut;
                body.put_i64(hi as i64);
                body.put_i64(lo as i64);
                let user_bytes = username.as_bytes();
                VarInt(user_bytes.len() as i32).encode(&mut body).ok()?;
                body.put_slice(user_bytes);
                Some(EncodedPacket { id: 0x02, body })
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
            // The V1_19_4 canonical bucket spans proto 755 - 763
            // (1.17 - 1.19.4) on the play side, but the LoginSuccess
            // wire shape splits at the **same proto 759 boundary** as
            // the V1_16_5 bucket above — Mojang only added the
            // properties trailer at 1.19 (proto 759). Per
            // minecraft.wiki §Login_Success per-version table and
            // BungeeCord `LoginSuccess.java::write`:
            //
            //   proto 755 - 758 (1.17 / 1.17.1 / 1.18 / 1.18.2):
            //       [16 raw UUID bytes][String username]
            //   proto 759+ (1.19+):
            //       [16 raw UUID bytes][String username]
            //       [VarInt prop_count][N × ProfileProperty]
            //
            // Writing properties unconditionally for 755-758 trails
            // ~1107 bytes of `textures` property after the 16-byte
            // username, the same exact `"Packet 2/2 ... found 1107
            // bytes extra"` cascade we fixed at the V1_16_5 bucket
            // for 1.16-1.18.2.
            if proto < 759 {
                use kojacoord_protocol::codec::Encode;
                use kojacoord_protocol::types::VarInt;
                let mut body = bytes::BytesMut::new();
                let (hi, lo) = uuid.as_u64_pair();
                use bytes::BufMut;
                body.put_i64(hi as i64);
                body.put_i64(lo as i64);
                let user_bytes = username.as_bytes();
                VarInt(user_bytes.len() as i32).encode(&mut body).ok()?;
                body.put_slice(user_bytes);
                Some(EncodedPacket { id: 0x02, body })
            } else {
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
            }
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

#[cfg(test)]
mod ship_check {
    //! LoginSuccess wire-shape regression pins. Every era boundary
    //! where Mojang added/removed a field is asserted here so future
    //! refactors can't quietly re-introduce the
    //! `"Packet 2/2 (vn/sy) was larger than I expected"` cascade.
    use super::*;
    use kojacoord_auth::ProfileProperty as AuthProp;
    use uuid::Uuid;

    fn profile_with_textures() -> (Uuid, String, Vec<AuthProp>) {
        let uuid = Uuid::from_u128(0x123456789ABCDEF0_0FEDCBA987654321);
        let username = "Vakea".to_string();
        // A realistic-sized textures property (Mojang's actual blob is
        // ~1100 bytes; we just need something non-trivial).
        let big_value: String = "a".repeat(1000);
        let big_sig: String = "b".repeat(684);
        let props = vec![AuthProp {
            name: "textures".into(),
            value: big_value,
            signature: Some(big_sig),
        }];
        (uuid, username, props)
    }

    fn build(proto: u32, canonical: CanonicalVersion) -> Vec<u8> {
        let (uuid, username, properties) = profile_with_textures();
        let profile = LoginProfile {
            uuid,
            username: &username,
            properties: &properties,
        };
        let pkt = build_login_success(canonical, proto, &profile).expect("must build");
        let mut out = Vec::new();
        out.push(pkt.id);
        out.extend_from_slice(&pkt.body);
        out
    }

    /// Body wire bytes for [16-UUID + VarInt(5) + "Vakea"] without
    /// any properties trailer. Used by the no-properties pins.
    fn expected_no_props_body_len() -> usize {
        // packet_id (1) + UUID (16) + VarInt(5) (1) + "Vakea" (5)
        1 + 16 + 1 + 5
    }

    #[test]
    fn proto_754_login_success_has_no_properties_trailer() {
        // 1.16.5
        let bytes = build(754, CanonicalVersion::V1_16_5);
        assert_eq!(
            bytes.len(),
            expected_no_props_body_len(),
            "1.16.5 LoginSuccess must not include properties trailer"
        );
    }

    #[test]
    fn proto_755_login_success_has_no_properties_trailer() {
        // 1.17 — the bug this turn reported.
        let bytes = build(755, CanonicalVersion::V1_19_4);
        assert_eq!(
            bytes.len(),
            expected_no_props_body_len(),
            "1.17 LoginSuccess must not include properties trailer — \
             Mojang added it at 1.19 (proto 759), not 1.17"
        );
    }

    #[test]
    fn proto_758_login_success_has_no_properties_trailer() {
        // 1.18.2
        let bytes = build(758, CanonicalVersion::V1_19_4);
        assert_eq!(
            bytes.len(),
            expected_no_props_body_len(),
            "1.18.2 LoginSuccess must not include properties trailer"
        );
    }

    #[test]
    fn proto_759_login_success_does_include_properties_trailer() {
        // 1.19 — sanity check the other direction.
        let bytes = build(759, CanonicalVersion::V1_19_4);
        assert!(
            bytes.len() > expected_no_props_body_len() + 1000,
            "1.19 LoginSuccess must include the properties trailer \
             (~1000+ bytes for textures), got {} bytes",
            bytes.len()
        );
    }
}
