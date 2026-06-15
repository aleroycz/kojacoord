//! Bridge a 1.20.2+ client to a 1.16.5 server (the reverse direction of
//! `v1_16_5_to_v1_20_4`). Same scope warnings apply — partial bridge only.
//!
//! Packet ID tables used (PrismarineJS minecraft-data proto.yml):
//!
//! ## 1.20.4 (proto 765) — login state C2S
//! - 0x00 Login Start
//! - 0x01 Encryption Response
//! - 0x02 Login Plugin Response
//! - 0x03 Login Acknowledged   (post-LoginSuccess, transitions to configuration)
//!
//! ## 1.20.4 — configuration state C2S
//! - 0x00 Client Information
//! - 0x01 Plugin Message
//! - 0x02 Finish Configuration (Ack)
//! - 0x03 Keep Alive
//! - 0x04 Pong
//! - 0x05 Resource Pack Response
//!
//! ## 1.20.4 — play state C2S (relevant subset)
//! - 0x05 Chat Message (signed)
//! - 0x06 Chat Command
//! - 0x14 Keep Alive
//!
//! ## 1.16.5 (proto 754) — login state C2S
//! - 0x00 Login Start
//! - 0x01 Encryption Response
//! - 0x02 Login Plugin Response
//!
//! ## 1.16.5 — play state C2S
//! - 0x03 Chat Message (plain text, no signing)
//! - 0x10 Keep Alive
//!
//! Configuration-phase bridging strategy: when the modern client sends
//! `Login Acknowledged` or any configuration-phase c2s packet to a 1.16.5
//! server (which knows nothing of that phase), we swallow it (`Drop`). The
//! sibling s2c converter is responsible for *synthesising* a fake
//! `Finish Configuration` after intercepting `LoginSuccess` so the client
//! transitions to play — that synthesis is still missing and currently
//! logged via `tracing::warn!`.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use kojacoord_protocol::codec::{Decode, Encode};
use kojacoord_protocol::types::VarInt;

use super::{build_payload, split_id};
use crate::converter::ConversionResult;

// ---- 1.20.4 source IDs ----
const V1204_LOGIN_C2S_LOGIN_START: u8 = 0x00;
const V1204_LOGIN_C2S_ENCRYPTION_RESPONSE: u8 = 0x01;
const V1204_LOGIN_C2S_LOGIN_ACK: u8 = 0x03;
// Configuration-state c2s. Numeric IDs overlap with play-state ids; we use the
// empty-body heuristic in the dispatcher to disambiguate.
const V1204_CONFIG_C2S_FINISH_CONFIGURATION_ACK: u8 = 0x02;

const V1204_PLAY_C2S_CHAT_COMMAND: u8 = 0x04;
const V1204_PLAY_C2S_CHAT_MESSAGE: u8 = 0x05;
/// Per BungeeCord `Protocol.java::TO_SERVER` KeepAlive table:
///   `map(MINECRAFT_1_20_2, 0x14)` then `map(MINECRAFT_1_20_3, 0x15)`.
/// Proto 765 covers 1.20.3 / 1.20.4 → ID 0x15. (The 0x14 value was
/// the 1.20.2 ID; using it on a 1.20.4 client desyncs every
/// keepalive and the connection times out after ~30 s.)
const V1204_PLAY_C2S_KEEP_ALIVE: u8 = 0x15;

// ---- 1.16.5 target IDs ----
const V165_LOGIN_C2S_LOGIN_START: u8 = 0x00;
const V165_LOGIN_C2S_ENCRYPTION_RESPONSE: u8 = 0x01;

const V165_PLAY_C2S_CHAT_MESSAGE: u8 = 0x03;
const V165_PLAY_C2S_KEEP_ALIVE: u8 = 0x10;

pub fn convert_c2s(payload: Bytes, client_proto: u32) -> ConversionResult {
    let Some((id, body)) = split_id(payload.clone()) else {
        return ConversionResult::Passthrough;
    };

    match id {
        // Login
        V1204_LOGIN_C2S_LOGIN_START => c2s_login_start(body),
        V1204_LOGIN_C2S_ENCRYPTION_RESPONSE => c2s_login_encryption_response(body),
        V1204_LOGIN_C2S_LOGIN_ACK => c2s_login_ack_swallow(client_proto),

        // Configuration-state Finish Configuration Acknowledged: heuristically
        // empty-body 0x02 sent right after the client transitions out of
        // configuration. The legacy server has no concept of it; drop.
        V1204_CONFIG_C2S_FINISH_CONFIGURATION_ACK if body.is_empty() => {
            tracing::trace!("swallowed c2s Finish Configuration Acknowledged for legacy backend");
            ConversionResult::Drop
        },

        // Play (and overlapping configuration IDs — see note in module doc)
        V1204_PLAY_C2S_CHAT_COMMAND => c2s_play_chat_command(body),
        V1204_PLAY_C2S_CHAT_MESSAGE => c2s_play_chat_strip_signature(body),
        V1204_PLAY_C2S_KEEP_ALIVE => c2s_play_keep_alive(body),

        _ => ConversionResult::Passthrough,
    }
}

// ============================================================================
// Login state
// ============================================================================

fn c2s_login_start(mut body: Bytes) -> ConversionResult {
    // 1.20.4 Login Start: String(name), UUID(player).
    // 1.20.2 had: String, Option<sig data>, Option<UUID>.
    // 1.16.5 Login Start: String(name) only.
    let Ok(name) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    name.encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V165_LOGIN_C2S_LOGIN_START, &out)])
}

fn c2s_login_encryption_response(mut body: Bytes) -> ConversionResult {
    // 1.19+: Length-prefixed shared secret, then either:
    //   - has_verify_token=true, Length-prefixed verify token
    //   - has_verify_token=false, Salt(i64), Length-prefixed sig
    // 1.16.5: Length-prefixed shared secret, Length-prefixed verify token.
    let Ok(secret_len) = VarInt::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let secret_len = secret_len.0 as usize;
    if body.remaining() < secret_len {
        return ConversionResult::Passthrough;
    }
    let secret = body.split_to(secret_len);

    // Try 1.19 has-verify-token boolean; if absent, fall through.
    if body.remaining() < 1 {
        return ConversionResult::Passthrough;
    }
    let has_token = body.get_u8() != 0;
    let token_bytes = if has_token {
        let Ok(tlen) = VarInt::decode(&mut body) else {
            return ConversionResult::Passthrough;
        };
        let tlen = tlen.0 as usize;
        if body.remaining() < tlen {
            return ConversionResult::Passthrough;
        }
        body.split_to(tlen)
    } else {
        // Signature-based: we cannot recover a verify token from a signature
        // because the server's verify token bytes are random and the proxy
        // doesn't know them. Drop for now — forwarding would need token recovery.
        tracing::warn!(
            target: "converter",
            from = "1.20.4",
            to = "1.16.5",
            "dropping Encryption Response with signature-only verify (no token to forward)"
        );
        return ConversionResult::Drop;
    };

    let mut out = BytesMut::new();
    VarInt(secret.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(&secret);
    VarInt(token_bytes.len() as i32).encode(&mut out).unwrap();
    out.extend_from_slice(&token_bytes);
    ConversionResult::Converted(vec![build_payload(
        V165_LOGIN_C2S_ENCRYPTION_RESPONSE,
        &out,
    )])
}

fn c2s_login_ack_swallow(client_proto: u32) -> ConversionResult {
    // 1.16.5 has no configuration phase, so we swallow the LoginAcknowledged
    // c2s packet (the legacy server would error on it). We must also drive the
    // modern client out of the configuration phase that the client transitions
    // into immediately after sending LoginAck — otherwise the client stalls
    // waiting for Registry Data + Finish Configuration packets that will never
    // come.
    //
    // For 1.20.2–1.20.4 (proto 764–765) a bare FinishConfiguration suffices
    // because the client keeps built-in defaults. For 1.20.5+ (proto 766+)
    // the client clears its registries on entering config, so we must also
    // inject ClientboundRegistryData packets before FinishConfiguration.
    match crate::config_synthesis::build_cfg_packets(client_proto) {
        Ok(packets) => {
            if packets.is_empty() {
                tracing::warn!(client_proto, "build_cfg_packets returned no packets");
                ConversionResult::Drop
            } else {
                ConversionResult::InjectS2C(packets.into_iter().map(Bytes::from).collect())
            }
        },
        Err(e) => {
            tracing::warn!(client_proto, error = %e, "failed to build config-phase packets");
            ConversionResult::Drop
        },
    }
}

// ============================================================================
// Play state
// ============================================================================

fn c2s_play_chat_command(mut body: Bytes) -> ConversionResult {
    // 1.20.4 Chat Command: String command, Long timestamp, Long salt,
    //   VarInt(argument_count), Array<(String name, Vec<u8 256> signature)>,
    //   VarInt message_count, BitSet acks.
    // 1.16.5 has no dedicated chat-command packet — commands travel as a
    // chat message starting with "/". We extract the command text, prefix it
    // with "/", and emit it as a 1.16.5 Chat Message. All signature data is
    // discarded since the 1.16.5 server doesn't verify chat.
    let Ok(cmd) = String::decode(&mut body) else {
        tracing::warn!("failed to decode 1.20.4 chat-command; dropping");
        return ConversionResult::Drop;
    };
    let mut out = BytesMut::new();
    let truncated: String = format!("/{}", cmd).chars().take(256).collect();
    truncated.encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V165_PLAY_C2S_CHAT_MESSAGE, &out)])
}

fn c2s_play_chat_strip_signature(mut body: Bytes) -> ConversionResult {
    // 1.20.4 Chat Message: String, Long(timestamp), Long(salt),
    //   Option<sig 256 bytes>, VarInt(msg_count), BitSet(acks 20 bits)
    // 1.16.5 Chat Message: String only (max 256 chars).
    let Ok(msg) = String::decode(&mut body) else {
        return ConversionResult::Passthrough;
    };
    let mut out = BytesMut::new();
    // 1.16.5 caps chat at 256 chars; truncate defensively.
    let truncated: String = msg.chars().take(256).collect();
    truncated.encode(&mut out).unwrap();
    ConversionResult::Converted(vec![build_payload(V165_PLAY_C2S_CHAT_MESSAGE, &out)])
}

fn c2s_play_keep_alive(mut body: Bytes) -> ConversionResult {
    if body.remaining() < 8 {
        return ConversionResult::Passthrough;
    }
    let id = body.get_i64();
    let mut out = BytesMut::with_capacity(8);
    out.put_i64(id);
    ConversionResult::Converted(vec![build_payload(V165_PLAY_C2S_KEEP_ALIVE, &out)])
}

pub fn convert_s2c(payload: Bytes) -> ConversionResult {
    // S2C from a 1.20.4 server to a 1.16.5 client is the inverse — owned
    // entirely by the sibling `v1_16_5_to_v1_20_4` module which handles the
    // opposite direction. No-op here for symmetry with how the v1_8 pair is
    // structured.
    let _ = payload;
    ConversionResult::Passthrough
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_string(s: &str) -> Vec<u8> {
        let mut b = BytesMut::new();
        s.to_string().encode(&mut b).unwrap();
        b.to_vec()
    }

    #[test]
    fn login_start_drops_uuid_suffix() {
        let mut body = BytesMut::new();
        body.extend_from_slice(&enc_string("alex"));
        body.put_i64(0xDEADBEEF);
        body.put_i64(0xCAFEBABE);
        let payload = build_payload(V1204_LOGIN_C2S_LOGIN_START, &body);
        let out = convert_c2s(payload, 765);
        match out {
            ConversionResult::Converted(p) => {
                let (id, mut rest) = split_id(p[0].clone()).unwrap();
                assert_eq!(id, V165_LOGIN_C2S_LOGIN_START);
                assert_eq!(String::decode(&mut rest).unwrap(), "alex");
                assert_eq!(rest.remaining(), 0);
            },
            _ => panic!("expected Converted"),
        }
    }

    #[test]
    fn login_ack_injects_finish_configuration() {
        let payload = build_payload(V1204_LOGIN_C2S_LOGIN_ACK, &[]);
        match convert_c2s(payload, 765) {
            ConversionResult::InjectS2C(packets) => {
                assert_eq!(packets.len(), 1, "proto 765: exactly one synthetic packet");
                assert_eq!(packets[0].len(), 1, "id varint only, empty body");
                assert_eq!(packets[0][0], 0x02);
            },
            other => panic!("expected InjectS2C, got {:?}", other_label(&other)),
        }
    }

    #[test]
    fn login_ack_766_injects_registry_data_then_finish() {
        let payload = build_payload(V1204_LOGIN_C2S_LOGIN_ACK, &[]);
        match convert_c2s(payload, 766) {
            ConversionResult::InjectS2C(packets) => {
                assert!(
                    packets.len() > 1,
                    "proto 766: expected RegistryData + FinishConfiguration, got {} packets",
                    packets.len()
                );
                let last = &packets[packets.len() - 1];
                assert_eq!(last[0], 0x03, "last packet should be FinishConfiguration (0x03)");
            },
            other => panic!("expected InjectS2C, got {:?}", other_label(&other)),
        }
    }

    #[test]
    fn finish_configuration_ack_is_dropped() {
        let payload = build_payload(V1204_CONFIG_C2S_FINISH_CONFIGURATION_ACK, &[]);
        assert!(matches!(convert_c2s(payload, 765), ConversionResult::Drop));
    }

    fn other_label(r: &ConversionResult) -> &'static str {
        match r {
            ConversionResult::Passthrough => "Passthrough",
            ConversionResult::Converted(_) => "Converted",
            ConversionResult::Drop => "Drop",
            ConversionResult::InjectS2C(_) => "InjectS2C",
        }
    }

    #[test]
    fn chat_strips_signature_and_metadata() {
        let mut body = BytesMut::new();
        body.extend_from_slice(&enc_string("hello"));
        body.put_i64(123); // timestamp
        body.put_i64(456); // salt
        body.put_u8(0); // no signature
        VarInt(0).encode(&mut body).unwrap();
        // BitSet skipped — converter only reads up to the chat string.
        let payload = build_payload(V1204_PLAY_C2S_CHAT_MESSAGE, &body);
        let out = convert_c2s(payload, 765);
        match out {
            ConversionResult::Converted(p) => {
                let (id, mut rest) = split_id(p[0].clone()).unwrap();
                assert_eq!(id, V165_PLAY_C2S_CHAT_MESSAGE);
                assert_eq!(String::decode(&mut rest).unwrap(), "hello");
                assert_eq!(rest.remaining(), 0);
            },
            _ => panic!("expected Converted"),
        }
    }

    #[test]
    fn encryption_response_with_token_passes_through_shape() {
        let mut body = BytesMut::new();
        let secret = [0xAAu8; 16];
        let token = [0xBBu8; 4];
        VarInt(secret.len() as i32).encode(&mut body).unwrap();
        body.extend_from_slice(&secret);
        body.put_u8(1); // has verify token
        VarInt(token.len() as i32).encode(&mut body).unwrap();
        body.extend_from_slice(&token);
        let payload = build_payload(V1204_LOGIN_C2S_ENCRYPTION_RESPONSE, &body);
        let out = convert_c2s(payload, 765);
        match out {
            ConversionResult::Converted(p) => {
                let (id, mut rest) = split_id(p[0].clone()).unwrap();
                assert_eq!(id, V165_LOGIN_C2S_ENCRYPTION_RESPONSE);
                let slen = VarInt::decode(&mut rest).unwrap().0 as usize;
                assert_eq!(slen, secret.len());
                let s = rest.split_to(slen);
                assert_eq!(&s[..], &secret[..]);
                let tlen = VarInt::decode(&mut rest).unwrap().0 as usize;
                assert_eq!(tlen, token.len());
                let t = rest.split_to(tlen);
                assert_eq!(&t[..], &token[..]);
            },
            _ => panic!("expected Converted"),
        }
    }
}
