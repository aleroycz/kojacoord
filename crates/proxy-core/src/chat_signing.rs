//! Chat-signing translation for 1.19+ bridges.
//!
//! 1.19 added cryptographic chat signing — `ServerboundChatMessage`
//! carries a Mojang-signed timestamp + salt + signature, and the
//! clientbound side splits into `SystemChat`/`PlayerChat`. Older
//! versions don't know about any of that. When we bridge across that
//! boundary the signature fields have to be stripped on the way down
//! (1.19+ client → 1.18 server) or fabricated as "unsigned" on the way
//! up. We never re-sign at the proxy — that would require Mojang
//! credentials.

use bytes::{Buf, BytesMut};
use kojacoord_protocol::{
    codec::{Decode, Encode},
    types::VarInt,
    ProtocolVersion,
};

/// True for 1.19+ (proto 759+) — the version that introduced signed
/// chat. Thin wrapper around [`ProtocolVersion::has_chat_signing`] so
/// call sites in this module read clearly.
pub fn supports_chat_signing(protocol_version: u32) -> bool {
    ProtocolVersion::from_id(protocol_version).has_chat_signing()
}

/// Inverse of [`supports_chat_signing`] — the pre-1.19 cases where any
/// signature field on the wire is itself a protocol error.
pub fn requires_unsigned_chat(protocol_version: u32) -> bool {
    !ProtocolVersion::from_id(protocol_version).has_chat_signing()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatSigningMode {
    /// Pass the original signature through unchanged. Used when both
    /// ends speak the signed-chat protocol.
    Signed,
    /// Strip signature fields on the way through. Used whenever one
    /// side can't validate them — including any time we can't be sure
    /// re-signing would round-trip correctly.
    Unsigned,
    /// Leave whatever's on the wire alone (both sides predate signed
    /// chat, so there's nothing to translate).
    Preserve,
}

/// Pick a [`ChatSigningMode`] from the client/backend version pair.
/// "Mixed" cases fall to [`Unsigned`][ChatSigningMode::Unsigned] —
/// the safest path that won't kick the client for a bad signature.
pub fn determine_signing_mode(client_protocol: u32, backend_protocol: u32) -> ChatSigningMode {
    let client_supports = supports_chat_signing(client_protocol);
    let backend_supports = supports_chat_signing(backend_protocol);
    let client_requires = requires_unsigned_chat(client_protocol);
    let backend_requires = requires_unsigned_chat(backend_protocol);

    match (
        client_supports,
        backend_supports,
        client_requires,
        backend_requires,
    ) {
        // Both support signing - preserve
        (true, true, false, false) => ChatSigningMode::Preserve,

        // Client supports, backend doesn't - strip
        (true, false, false, true) => ChatSigningMode::Unsigned,

        // Client doesn't support, backend does - strip
        (false, true, true, false) => ChatSigningMode::Unsigned,

        // Both don't support - preserve (no signing anyway)
        (false, false, true, true) => ChatSigningMode::Preserve,

        // Mixed cases - default to unsigned for safety
        _ => ChatSigningMode::Unsigned,
    }
}

/// Rewrite a `ServerboundChatMessage` so it parses on a pre-1.19
/// server: keeps message + timestamp, clears the optional UUID and
/// signature byte-array flags, and zeroes the salt (1.19.3+). The
/// caller is responsible for only invoking this when the client is
/// 1.19+ (otherwise there's no signature to strip).
pub fn strip_chat_signature(payload: &[u8], protocol_version: u32) -> Result<Vec<u8>, String> {
    let canonical = ProtocolVersion::from_id(protocol_version);

    if !canonical.has_chat_signing() {
        // No signature to strip
        return Ok(payload.to_vec());
    }

    let mut src = bytes::Bytes::copy_from_slice(payload);

    // Decode packet ID
    let packet_id =
        VarInt::decode(&mut src).map_err(|e| format!("Failed to decode packet ID: {}", e))?;

    // Decode message
    let message =
        String::decode(&mut src).map_err(|e| format!("Failed to decode message: {}", e))?;

    // Decode timestamp (1.19+)
    let timestamp =
        i64::decode(&mut src).map_err(|e| format!("Failed to decode timestamp: {}", e))?;

    // For 1.19+, we need to skip signature fields
    // The signature fields are:
    // - Optional<UUID> (bool prefix + UUID if true)
    // - Optional<ByteArray> (bool prefix + bytes if true)

    // Skip signature UUID if present
    let has_signature =
        bool::decode(&mut src).map_err(|e| format!("Failed to decode has_signature: {}", e))?;
    if has_signature {
        // Skip 16-byte UUID — there's no `Decode` impl for u128, and we
        // only need to step past the field, not interpret it.
        if src.remaining() < 16 {
            return Err("truncated signature UUID".into());
        }
        src.advance(16);
    }

    // Skip signature bytes if present
    let has_signature_bytes = bool::decode(&mut src)
        .map_err(|e| format!("Failed to decode has_signature_bytes: {}", e))?;
    if has_signature_bytes {
        let len = i32::decode(&mut src)
            .map_err(|e| format!("Failed to decode signature length: {}", e))?;
        if len > 0 {
            let len_usize = len as usize;
            if len_usize > src.remaining() {
                return Err("signature byte length exceeds remaining buffer".into());
            }
            let _ = src.split_to(len_usize);
        }
    }

    // Skip salt (1.19.3+)
    if canonical.id() >= 761 {
        let _ = u64::decode(&mut src); // Skip salt
    }

    // Rebuild packet without signature fields
    let mut rebuilt = BytesMut::new();

    // Encode packet ID
    packet_id
        .encode(&mut rebuilt)
        .map_err(|e| format!("Failed to encode packet ID: {}", e))?;

    // Encode message
    message
        .encode(&mut rebuilt)
        .map_err(|e| format!("Failed to encode message: {}", e))?;

    // Encode timestamp
    timestamp
        .encode(&mut rebuilt)
        .map_err(|e| format!("Failed to encode timestamp: {}", e))?;

    // Encode has_signature = false
    false
        .encode(&mut rebuilt)
        .map_err(|e| format!("Failed to encode has_signature: {}", e))?;

    // Encode has_signature_bytes = false
    false
        .encode(&mut rebuilt)
        .map_err(|e| format!("Failed to encode has_signature_bytes: {}", e))?;

    // Encode salt = 0 (1.19.3+)
    if canonical.id() >= 761 {
        0u64.encode(&mut rebuilt)
            .map_err(|e| format!("Failed to encode salt: {}", e))?;
    }

    // Copy remaining fields (if any) from original packet
    // This preserves any fields that come after the signature section
    rebuilt.extend_from_slice(&src);

    Ok(rebuilt.to_vec())
}
