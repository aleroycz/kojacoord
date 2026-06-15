//! Configuration-phase shimming for the 1.20.2 boundary.
//!
//! 1.20.2 introduced a Configuration state between Login and Play —
//! the server pushes registries, tags, and resource-pack info before
//! handing control to Play. Pre-1.20.2 servers don't run that phase at
//! all; modern clients will sit forever waiting for `FinishConfiguration`
//! if we just forward the legacy `LoginSuccess` straight through.
//!
//! When the client is 1.20.2+ and the backend isn't, we synthesise the
//! configuration phase packets here so the client transitions into Play
//! and starts accepting the backend's legacy join sequence.
//!
//! **1.20.2–1.20.4 (proto 764–765):** The client falls back to built-in
//! defaults when registry data is absent, so a bare `FinishConfiguration`
//! suffices.
//!
//! **1.20.5+ (proto 766+):** The client *clears* its registries at the
//! start of the configuration phase and only repopulates them from
//! explicit `ClientboundRegistryData` packets. Without them the client
//! cannot resolve `dimension_type = VarInt(0)` in JoinGame and
//! disconnects. We inject the full registry set before FinishConfiguration.

use bytes::BytesMut;
use kojacoord_protocol::{codec::Encode, types::VarInt, Epoch, ProtocolVersion};

/// True for 1.20.2+ (proto 764+) — versions that run the configuration
/// state between Login and Play.
pub fn has_configuration_phase(protocol_version: u32) -> bool {
    ProtocolVersion::from_id(protocol_version).has_configuration_phase()
}

/// True when the client expects a config phase the backend won't
/// produce. Inverse direction is handled by swallowing packets in the
/// relay, not by synthesis.
pub fn needs_synthesis(client_protocol: u32, backend_protocol: u32) -> bool {
    has_configuration_phase(client_protocol) && !has_configuration_phase(backend_protocol)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynthesisMode {
    /// Both ends agree; relay forwards untouched.
    None,
    /// Client expects config phase, backend doesn't — proxy injects
    /// `RegistryData` (proto 766+) + `FinishConfiguration` toward the
    /// client after we swallow its `LoginAcknowledged`.
    ClientSide,
    /// Backend expects config phase, client doesn't — relay swallows
    /// the backend's config-phase packets and replies on the client's
    /// behalf.
    BackendSide,
}

/// Pick a [`SynthesisMode`] from the client/backend version pair.
pub fn determine_synthesis_mode(client_protocol: u32, backend_protocol: u32) -> SynthesisMode {
    match (
        has_configuration_phase(client_protocol),
        has_configuration_phase(backend_protocol),
    ) {
        (true, false) => SynthesisMode::ClientSide,
        (false, true) => SynthesisMode::BackendSide,
        _ => SynthesisMode::None,
    }
}

/// Build all configuration-phase packets the proxy must inject toward a
/// modern client whose backend has no configuration phase.
///
/// Returns an ordered list of raw framed packets (VarInt-prefixed packet id
/// + body) ready to write to the client stream:
///
/// 1. `ClientboundRegistryData` packets (one per registry) — **only for
///    proto 766+** (1.20.5+), where the client clears its registries on
///    entering config and needs them explicitly repopulated.
/// 2. `FinishConfiguration` (empty body) — signals "config done, transition
///    to play".
///
/// Returns `Err` if called on a pre-1.20.2 version where the config phase
/// doesn't exist.
pub fn build_cfg_packets(protocol_version: u32) -> Result<Vec<Vec<u8>>, String> {
    let canonical = ProtocolVersion::from_id(protocol_version);

    if !has_configuration_phase(protocol_version) {
        return Err("Protocol version does not have configuration phase".into());
    }

    let mut packets = Vec::new();

    // Registry data — only needed for 1.20.5+ (proto 766+).
    // 1.20.2–1.20.4 clients keep built-in defaults when registry data is
    // absent, so we skip this step for them.
    if protocol_version >= 766 {
        if let Some(bundle) = crate::net::registry_data::bundle_for_proto(protocol_version) {
            let id_registry =
                crate::net::packet_ids::cb_config(protocol_version, "ClientboundRegistryData");
            if id_registry == 0xFF {
                tracing::warn!(
                    protocol_version,
                    "config synthesis: no ClientboundRegistryData id found — \
                     1.20.5+ client will likely reject JoinGame"
                );
            } else {
                if crate::net::registry_data::bundle_is_fallback(protocol_version) {
                    tracing::warn!(
                        protocol_version,
                        "config synthesis: using best-effort registry bundle — \
                         capture exact data if the client rejects it"
                    );
                }
                match crate::net::registry_data::parse_bundle(bundle) {
                    Ok(bodies) => {
                        tracing::debug!(
                            protocol_version,
                            registries = bodies.len(),
                            "config synthesis: injecting RegistryData packets"
                        );
                        for body in bodies {
                            let mut pkt = BytesMut::new();
                            VarInt(id_registry as i32)
                                .encode(&mut pkt)
                                .map_err(|e| format!("encode registry data id: {}", e))?;
                            pkt.extend_from_slice(body);
                            packets.push(pkt.to_vec());
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            protocol_version,
                            error = %e,
                            "config synthesis: failed to parse registry bundle — skipping"
                        );
                    },
                }
            }
        }
    }

    // FinishConfiguration packet id (clientbound):
    //   1.20.2 – 1.20.4 (protos 764, 765): 0x02
    //   1.20.5 / 1.20.6 (proto 766):        0x03
    //   1.21+           (proto >= 767):     0x03
    let finish_id = match canonical.epoch() {
        Epoch::V1_20 => {
            if canonical.id() >= 766 {
                0x03
            } else {
                0x02
            }
        },
        Epoch::V1_21Plus => 0x03,
        _ => return Err("config synthesis only valid for 1.20.2+".into()),
    };

    let mut finish = BytesMut::new();
    VarInt(finish_id as i32)
        .encode(&mut finish)
        .map_err(|e| format!("encode finish id: {}", e))?;
    packets.push(finish.to_vec());

    Ok(packets)
}

/// Encode the bare clientbound `FinishConfiguration` packet (no body —
/// the packet is just an id signalling "config done, transition to
/// play"). Returns `Err` if called on a pre-1.20.2 version where the
/// packet doesn't exist.
///
/// Prefer [`build_cfg_packets`] for new code — that function also injects
/// the `RegistryData` packets required by 1.20.5+ clients.
pub fn build_cfg_finish_packet(protocol_version: u32) -> Result<Vec<u8>, String> {
    let packets = build_cfg_packets(protocol_version)?;
    packets
        .into_iter()
        .last()
        .ok_or_else(|| "no packets produced".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_765_produces_only_finish() {
        let packets = build_cfg_packets(765).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0][0], 0x02);
    }

    #[test]
    fn proto_766_includes_registry_data() {
        let packets = build_cfg_packets(766).unwrap();
        assert!(packets.len() > 1, "expected RegistryData + Finish, got {} packets", packets.len());
        assert_eq!(packets[packets.len() - 1][0], 0x03, "last packet should be FinishConfiguration");
    }

    #[test]
    fn proto_below_764_returns_error() {
        assert!(build_cfg_packets(754).is_err());
    }

    #[test]
    fn needs_synthesis_modern_client_legacy_backend() {
        assert!(needs_synthesis(765, 754));
        assert!(!needs_synthesis(754, 754));
        assert!(!needs_synthesis(754, 765));
    }
}
