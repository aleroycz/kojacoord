use bytes::{Bytes, BytesMut};
use kojacoord_protocol::{codec::Encode, types::VarInt, ProtocolVersion};
use uuid::Uuid;

use crate::{
    modloader,
    packet_ids::{cb_chat_id, cb_play, cb_plugin_message_id, nearest, sb_plugin_message_id},
    plugin_decoder,
};

pub fn build_system_message_packet(text: &str, proto: u32) -> Bytes {
    let json = serde_json::json!({ "text": text, "color": "yellow" }).to_string();
    let pid = cb_chat_id(proto);
    let mut payload = BytesMut::new();
    VarInt(pid as i32).encode(&mut payload).unwrap();

    match nearest(proto) {
        ProtocolVersion::V1_6_4 | ProtocolVersion::V1_7_10 => {
            use kojacoord_protocol::versions::v1_7_10::play::ClientboundChatMessage;
            ClientboundChatMessage {
                json_message: json,
                position: 1,
            }
            .encode(&mut payload)
            .unwrap();
        },
        ProtocolVersion::V1_8 | ProtocolVersion::V1_12_2 => {
            use kojacoord_protocol::versions::v1_12_2::play::ClientboundChatMessage;
            ClientboundChatMessage {
                json_message: json,
                position: 1,
            }
            .encode(&mut payload)
            .unwrap();
        },
        ProtocolVersion::V1_16_5 => {
            use kojacoord_protocol::versions::v1_16_5::play::ClientboundChatMessage;
            ClientboundChatMessage {
                json_message: json,
                position: 1,
                sender: Uuid::nil(),
            }
            .encode(&mut payload)
            .unwrap();
        },
        _ => {
            use kojacoord_protocol::versions::v1_20_4::play::ClientboundSystemChat;
            ClientboundSystemChat {
                content: json,
                overlay: false,
            }
            .encode(&mut payload)
            .unwrap();
        },
    }

    payload.freeze()
}

pub fn build_plugin_message_packet(channel: &str, data: &[u8], proto: u32) -> Bytes {
    let pid = cb_plugin_message_id(proto);
    let body = plugin_decoder::encode_plugin_message(channel, data, proto).unwrap_or_else(|_| {
        let mut b = BytesMut::new();
        channel.to_owned().encode(&mut b).unwrap();
        b.extend_from_slice(data);
        b.freeze()
    });
    let mut payload = BytesMut::with_capacity(1 + body.len());
    VarInt(pid as i32).encode(&mut payload).unwrap();
    payload.extend_from_slice(&body);
    payload.freeze()
}

pub fn build_serverbound_plugin_message_packet(channel: &str, data: &[u8], proto: u32) -> Bytes {
    let pid = sb_plugin_message_id(proto);
    let body = plugin_decoder::encode_plugin_message(channel, data, proto).unwrap_or_else(|_| {
        let mut b = BytesMut::new();
        channel.to_owned().encode(&mut b).unwrap();
        b.extend_from_slice(data);
        b.freeze()
    });
    let mut payload = BytesMut::with_capacity(1 + body.len());
    VarInt(pid as i32).encode(&mut payload).unwrap();
    payload.extend_from_slice(&body);
    payload.freeze()
}

pub fn build_brand_packet(kind: modloader::ModloaderKind, proto: u32) -> Bytes {
    let brand_str: &str = match kind {
        modloader::ModloaderKind::Fml1 | modloader::ModloaderKind::Fml2 => "fml,bukkit",
        modloader::ModloaderKind::Fml3 => "forge",
        modloader::ModloaderKind::NeoForge => "neoforge",
        modloader::ModloaderKind::Fabric => "fabric",
        modloader::ModloaderKind::Unknown | modloader::ModloaderKind::Vanilla => "Kojacoord",
    };

    let pid = cb_plugin_message_id(proto);
    let mut payload = BytesMut::new();
    VarInt(pid as i32).encode(&mut payload).unwrap();

    if proto <= 47 {
        "MC|Brand".to_owned().encode(&mut payload).unwrap();
    } else {
        "minecraft:brand".to_owned().encode(&mut payload).unwrap();
    }
    brand_str.to_owned().encode(&mut payload).unwrap();

    payload.freeze()
}

pub fn build_disconnect_packet(json_reason: &str, proto: u32) -> Bytes {
    let pkt_id = cb_play(proto, "ClientboundDisconnect");
    let mut payload = BytesMut::new();
    VarInt(pkt_id as i32).encode(&mut payload).unwrap();

    match nearest(proto) {
        ProtocolVersion::V1_6_4 => {
            use kojacoord_protocol::versions::v1_6_4::play::ClientboundDisconnect;
            ClientboundDisconnect {
                reason: json_reason.to_string(),
            }
            .encode(&mut payload)
            .unwrap();
        },
        ProtocolVersion::V1_7_10 => {
            use kojacoord_protocol::versions::v1_7_10::play::ClientboundDisconnect;
            ClientboundDisconnect {
                reason: json_reason.to_string(),
            }
            .encode(&mut payload)
            .unwrap();
        },
        ProtocolVersion::V1_8 | ProtocolVersion::V1_12_2 => {
            use kojacoord_protocol::versions::v1_12_2::play::ClientboundDisconnect;
            ClientboundDisconnect {
                reason: json_reason.to_string(),
            }
            .encode(&mut payload)
            .unwrap();
        },
        ProtocolVersion::V1_16_5 => {
            use kojacoord_protocol::versions::v1_16_5::play::ClientboundDisconnect;
            ClientboundDisconnect {
                reason: json_reason.to_string(),
            }
            .encode(&mut payload)
            .unwrap();
        },
        ProtocolVersion::V1_19_4 => {
            use kojacoord_protocol::versions::v1_19_4::play::ClientboundDisconnect;
            ClientboundDisconnect {
                reason: json_reason.to_string(),
            }
            .encode(&mut payload)
            .unwrap();
        },
        ProtocolVersion::V1_20_4 => {
            use kojacoord_protocol::versions::v1_20_4::play::ClientboundDisconnect;
            ClientboundDisconnect {
                reason: json_reason.to_string(),
            }
            .encode(&mut payload)
            .unwrap();
        },
        ProtocolVersion::V1_21 => {
            use kojacoord_protocol::versions::v1_21::play::ClientboundDisconnect;
            ClientboundDisconnect {
                reason: json_reason.to_string(),
            }
            .encode(&mut payload)
            .unwrap();
        },
        _ => {
            let reason_bytes = json_reason.as_bytes();
            VarInt(reason_bytes.len() as i32)
                .encode(&mut payload)
                .unwrap();
            payload.extend_from_slice(reason_bytes);
        },
    }

    payload.freeze()
}

/// Build a clientbound `BlockUpdate` packet (single-block change) that makes
/// the client render `block_state_id` at position (x, y, z).
///
/// Used by the XRay honeypot system to inject fake ore blocks into the
/// client's world without touching the real server's block state.
///
/// Protocol version mapping:
/// | Version | Packet ID | Position encoding         |
/// |---------|-----------|---------------------------|
/// | 1.7     | 0x23      | i32 x + u8 y + i32 z      |
/// | 1.8-1.12| 0x23/0x0B | packed i64                 |
/// | 1.13-1.17| 0x0B     | packed i64 + VarInt state  |
/// | 1.18+   | 0x09      | packed i64 + VarInt state  |
/// | 1.21    | 0x09      | same as 1.18               |
pub fn build_block_update_packet(x: i32, y: i32, z: i32, block_state_id: u32, proto: u32) -> Bytes {
    use kojacoord_protocol::VersionRegistry;
    let ver = VersionRegistry::nearest(proto);

    // Pack (x, y, z) into a single i64 block position.
    // 1.14+ format (pack_pos_new):
    //   bits 63-38: X (26-bit signed)
    //   bits 37-12: Z (26-bit signed)
    //   bits 11-0:  Y (12-bit signed)
    let pack_pos_new = |bx: i32, by: i32, bz: i32| -> i64 {
        (((bx & 0x3FFFFFF) as i64) << 38)
            | (((bz & 0x3FFFFFF) as i64) << 12)
            | ((by & 0xFFF) as i64)
    };
    // Legacy format (1.8-1.13):
    //   bits 63-38: X (26-bit signed)
    //   bits 37-26: Y (12-bit signed)
    //   bits 25-0:  Z (26-bit signed)
    let pack_pos_legacy = |bx: i32, by: i32, bz: i32| -> i64 {
        (((bx & 0x3FFFFFF) as i64) << 38)
            | (((by & 0xFFF) as i64) << 26)
            | ((bz & 0x3FFFFFF) as i64)
    };

    let mut payload = BytesMut::new();

    match ver {
        ProtocolVersion::V1_6_4 | ProtocolVersion::V1_7_10 => {
            // 1.7: packet 0x23 — Block Change
            // Fields: x(i32) y(u8) z(i32) block_type(VarInt) block_metadata(u8)
            VarInt(0x23_i32).encode(&mut payload).unwrap();
            x.encode(&mut payload).unwrap();
            (y as u8).encode(&mut payload).unwrap();
            z.encode(&mut payload).unwrap();
            // block_state_id encodes as type<<4|meta; pass as-is capped at VarInt
            VarInt(block_state_id as i32).encode(&mut payload).unwrap();
            0u8.encode(&mut payload).unwrap(); // metadata
        },
        ProtocolVersion::V1_8 | ProtocolVersion::V1_12_2 => {
            // 1.8/1.12: 0x23 — packed position + VarInt block data
            VarInt(0x23_i32).encode(&mut payload).unwrap();
            let pos = pack_pos_legacy(x, y, z);
            pos.encode(&mut payload).unwrap();
            VarInt(block_state_id as i32).encode(&mut payload).unwrap();
        },
        ProtocolVersion::V1_16_5 => {
            // 1.16: 0x0B — packed position + VarInt block state
            VarInt(0x0B_i32).encode(&mut payload).unwrap();
            pack_pos_new(x, y, z).encode(&mut payload).unwrap();
            VarInt(block_state_id as i32).encode(&mut payload).unwrap();
        },
        ProtocolVersion::V1_19_4 | ProtocolVersion::V1_20_4 | ProtocolVersion::V1_21 => {
            // 1.19-1.21: 0x09 — packed position + VarInt block state
            VarInt(0x09_i32).encode(&mut payload).unwrap();
            pack_pos_new(x, y, z).encode(&mut payload).unwrap();
            VarInt(block_state_id as i32).encode(&mut payload).unwrap();
        },
        _ => {
            // Unknown version: best-effort 0x09 format
            VarInt(0x09_i32).encode(&mut payload).unwrap();
            pack_pos_new(x, y, z).encode(&mut payload).unwrap();
            VarInt(block_state_id as i32).encode(&mut payload).unwrap();
        },
    }

    payload.freeze()
}
