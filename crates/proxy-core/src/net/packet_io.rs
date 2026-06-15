//! Length-prefixed Minecraft framing with optional zlib compression.
//!
//! Below the per-version typed packets, every Minecraft packet on the
//! wire is `<length: varint><[data]>`. When compression is negotiated
//! the body becomes `<uncompressed_length: varint><compressed_data>`
//! and packets above the threshold are zlib-deflated. This module is
//! the read/write half of that — everything above (`connection.rs`,
//! `relay.rs`) hands frames in and out as `Bytes`.
//!
//! Framing mode by protocol epoch (see
//! [`kojacoord_protocol::Epoch`]):
//!   * [`Epoch::PreNetty`] (1.6.x) — no varint length prefix; the
//!     packet id is one raw byte and each packet has a static size
//!     determined by its id. Compression never applies. Callers that
//!     bridge a 1.6 client must speak the legacy framing directly via
//!     [`write_legacy_bytes`] / [`read_legacy_byte`] and rely on the
//!     v1_6_x typed packets for size.
//!   * Modern (1.7+) — `<length: varint><body>` with optional
//!     zlib compression once the threshold has been negotiated. Handled
//!     by [`read_frame`] / [`write_packet`].
//!
//! [`is_pre_netty_proto`] is a thin helper around `Epoch::PreNetty` so
//! call sites don't have to import the protocol crate just to gate on
//! the framing mode.

use std::io::{Read, Write};

use bytes::{BufMut, Bytes, BytesMut};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use kojacoord_protocol::{
    codec::Encode, types::VarInt, Decode, Epoch, ProtocolError, VersionRegistry,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::buffer_pool::GLOBAL_BUFFER_POOL;
use crate::error::ConnectionError;

pub const NO_COMPRESSION: i32 = -1;

pub const MAX_PACKET_SIZE: usize = 2 * 1024 * 1024;

/// True if the given negotiated protocol speaks the pre-netty wire
/// format (1.6.x and earlier). Pre-netty connections have no varint
/// length prefix and no compression layer — calling the modern
/// `read_frame` / `write_packet` helpers on one corrupts the stream.
pub fn is_pre_netty_proto(proto: u32) -> bool {
    VersionRegistry::nearest(proto).epoch() == Epoch::PreNetty
}

/// Write raw legacy bytes verbatim. Use only when speaking the
/// pre-netty framing (1.6.x) — no length prefix, no compression. The
/// caller has already laid out the packet id and body per the legacy
/// protocol spec.
pub async fn write_legacy_bytes<W: AsyncWriteExt + Unpin>(
    dst: &mut W,
    raw: &[u8],
) -> Result<(), ConnectionError> {
    dst.write_all(raw).await?;
    dst.flush().await?;
    Ok(())
}

/// Read a single byte from a pre-netty stream. Used to peek at the
/// next packet id; subsequent fields must be read directly by the
/// typed v1_6_x decoder since each packet has a static-known shape.
pub async fn read_legacy_byte<R: AsyncReadExt + Unpin>(src: &mut R) -> Result<u8, ConnectionError> {
    Ok(src.read_u8().await?)
}

/// Encode a single varint-length-prefixed frame. Modern framing only
/// (1.7+). Pre-netty callers must use [`write_legacy_bytes`].
pub fn encode_frame(body: &[u8]) -> BytesMut {
    let mut out = GLOBAL_BUFFER_POOL.acquire(5 + body.len());
    VarInt(body.len() as i32)
        .encode(&mut out)
        .expect("encoding a VarInt into a BytesMut never fails");
    out.put_slice(body);
    out
}

/// Read one varint-length-prefixed frame from `src`. Modern framing
/// only — see [`is_pre_netty_proto`].
pub async fn read_frame<R: AsyncReadExt + Unpin>(src: &mut R) -> Result<Bytes, ConnectionError> {
    let len = read_varint(src).await?;
    if len < 0 || len as usize > MAX_PACKET_SIZE {
        return Err(ConnectionError::Protocol(ProtocolError::PacketTooLarge(
            len as usize,
            MAX_PACKET_SIZE,
        )));
    }
    let mut body = GLOBAL_BUFFER_POOL.acquire(len as usize);
    body.resize(len as usize, 0);
    src.read_exact(&mut body).await?;
    Ok(body.freeze())
}

pub fn compress(raw: &[u8], threshold: i32) -> BytesMut {
    let mut out = GLOBAL_BUFFER_POOL.acquire(raw.len() + 5);
    if raw.len() >= threshold.max(0) as usize {
        VarInt(raw.len() as i32)
            .encode(&mut out)
            .expect("VarInt encode into BytesMut never fails");
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(raw)
            .expect("zlib write into Vec never fails");
        let compressed = encoder.finish().expect("zlib finish into Vec never fails");
        out.put_slice(&compressed);
    } else {
        VarInt(0)
            .encode(&mut out)
            .expect("VarInt encode into BytesMut never fails");
        out.put_slice(raw);
    }
    out
}

pub fn decompress(body: Bytes) -> Result<Bytes, ConnectionError> {
    let mut cursor = body;
    let data_len = VarInt::decode(&mut cursor)
        .map_err(ConnectionError::Protocol)?
        .0;

    if data_len == 0 {
        return Ok(cursor);
    }
    if data_len < 0 || data_len as usize > MAX_PACKET_SIZE {
        return Err(ConnectionError::Protocol(ProtocolError::PacketTooLarge(
            data_len as usize,
            MAX_PACKET_SIZE,
        )));
    }

    let mut out = GLOBAL_BUFFER_POOL.acquire(data_len as usize);
    out.resize(data_len as usize, 0);
    let mut decoder = ZlibDecoder::new(cursor.as_ref());
    decoder.read_exact(&mut out).map_err(ConnectionError::Io)?;

    let mut trailing = [0u8; 1];
    match decoder.read(&mut trailing) {
        Ok(0) => {},
        Ok(_) => {
            return Err(ConnectionError::Protocol(ProtocolError::UnexpectedEof));
        },
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {},
        Err(e) => return Err(ConnectionError::Io(e)),
    }

    Ok(out.freeze())
}

pub fn encode_packet(raw: &[u8], threshold: i32) -> BytesMut {
    if threshold >= 0 {
        let compressed = compress(raw, threshold);
        let frame = encode_frame(&compressed);
        GLOBAL_BUFFER_POOL.release(compressed);
        frame
    } else {
        encode_frame(raw)
    }
}

pub async fn read_packet<R: AsyncReadExt + Unpin>(
    src: &mut R,
    threshold: i32,
) -> Result<Bytes, ConnectionError> {
    let body = read_frame(src).await?;
    if threshold >= 0 {
        decompress(body)
    } else {
        Ok(body)
    }
}

pub async fn write_packet<W: AsyncWriteExt + Unpin>(
    dst: &mut W,
    raw: &[u8],
    threshold: i32,
) -> Result<(), ConnectionError> {
    let frame = encode_packet(raw, threshold);
    dst.write_all(&frame).await?;
    dst.flush().await?;
    GLOBAL_BUFFER_POOL.release(frame);
    Ok(())
}

/// Proto-aware variant of [`write_packet`] for the *client* side of the
/// relay. `raw` is `[varint_packet_id][body]` for modern targets, and
/// `[raw_packet_id_byte][body]` for pre-netty (1.6.x) — the latter
/// happens after the converter already shaped the bytes into the
/// 1.6.x raw wire form. We bypass the varint-length framing AND
/// the compression layer entirely for pre-netty: those layers don't
/// exist on the 1.6 wire, and the 1.6.x client treats a leading
/// length VarInt as a garbage packet id.
///
/// `protocol_version` is the CLIENT's negotiated protocol number, not
/// the backend's. Always use the per-side value — the same relay can
/// have modern backend + pre-netty client where they differ.
pub async fn write_client_packet<W: AsyncWriteExt + Unpin>(
    dst: &mut W,
    raw: &[u8],
    protocol_version: u32,
    threshold: i32,
) -> Result<(), ConnectionError> {
    if is_pre_netty_proto(protocol_version) {
        // `raw` here is the converter's output, which for pre-netty
        // targets is already `[packet_id u8][body]`. Hand it straight
        // to `write_legacy_bytes` — no framing, no compression.
        write_legacy_bytes(dst, raw).await
    } else {
        write_packet(dst, raw, threshold).await
    }
}

/// Proto-aware variant of [`read_packet`] for the *client* side of the
/// relay. For modern (1.7+) clients this is identical to `read_packet`.
/// For pre-netty (1.6.x) clients we read the packet id byte directly
/// and consume exactly the bytes that packet's body shape requires —
/// the dispatch table for fixed-size shapes lives in
/// [`crate::limbo::read_and_discard_pre_netty`], reused here via the
/// per-shape length table. Variable-length packets (Chat, Plugin
/// Message, UpdateSign, ClickWindow, …) parse their own length prefix
/// inline.
pub async fn read_client_packet<R: AsyncReadExt + Unpin>(
    src: &mut R,
    protocol_version: u32,
    threshold: i32,
) -> Result<Bytes, ConnectionError> {
    if is_pre_netty_proto(protocol_version) {
        read_pre_netty_packet(src).await
    } else {
        read_packet(src, threshold).await
    }
}

/// Read a single pre-netty (1.6.x) packet off the wire. Pre-netty
/// frames have no length prefix and no compression — we read the
/// packet id byte first and then parse the exact body length from the
/// per-id shape table. Returned Bytes contain `[id][body]` so
/// downstream code can dispatch the same way as modern packets.
///
/// Variable-length packets (Chat, ClickWindow, UpdateSign, Plugin
/// Message, TabComplete, LocaleAndViewDistance, Disconnect) parse
/// their length-prefixed sub-fields inline. Unknown ids return an
/// `InvalidData` error so the caller can close the connection
/// gracefully rather than guess at the length.
async fn read_pre_netty_packet<R: AsyncReadExt + Unpin>(
    src: &mut R,
) -> Result<Bytes, ConnectionError> {
    use bytes::BufMut;
    let mut id_buf = [0u8; 1];
    src.read_exact(&mut id_buf).await?;
    let id = id_buf[0];

    // Fixed-shape c2s packets from the 1.6.4 client (per HexaCord
    // Packet*::readPacketData). Add new entries here as the relay
    // supports more interaction packets.
    let fixed_len: Option<usize> = match id {
        0x00 => Some(4),  // KeepAlive: i32
        0x07 => Some(9),  // UseEntity
        0x0A => Some(1),  // Player (on-ground only)
        0x0B => Some(33), // PlayerPosition
        0x0C => Some(9),  // PlayerLook
        0x0D => Some(41), // PlayerPositionLook
        0x0E => Some(11), // PlayerDigging
        0x10 => Some(2),  // HeldItemChange (i16)
        0x12 => Some(5),  // Animation
        0x13 => Some(9),  // EntityAction
        0x16 => Some(1),  // ClientCommand
        0x65 => Some(1),  // CloseWindow
        0x6A => Some(4),  // ConfirmTransaction
        0xCA => Some(9),  // PlayerAbilities (c2s)
        0xCD => Some(1),  // ClientStatus
        _ => None,
    };

    let mut out = BytesMut::with_capacity(64);
    out.put_u8(id);
    if let Some(n) = fixed_len {
        let mut body = vec![0u8; n];
        src.read_exact(&mut body).await?;
        out.put_slice(&body);
        return Ok(out.freeze());
    }

    // Variable-length packets — parse their length-prefixed
    // sub-fields and copy the bytes through verbatim.
    match id {
        0x03 | 0xCB => {
            // Chat / TabComplete: [u16 chars][UCS-2]
            let n = read_ucs2_into(src, &mut out).await?;
            let _ = n;
        },
        0x0F => {
            // PlayerBlockPlacement: [i32 x][i8 y][i32 z][i8 face]
            // [Slot item] [i8 cx][i8 cy][i8 cz].
            // Slot is variable; we drop straight to "read until next
            // unknown" by consuming a max-bounded chunk. For limbo
            // this packet shouldn't fire, but for backend relay we
            // need the bytes. Read the fixed prefix:
            let mut head = [0u8; 4 + 1 + 4 + 1];
            src.read_exact(&mut head).await?;
            out.put_slice(&head);
            // Slot: i16 item_id, then if != -1, i8 count + i16 damage
            // + i16 nbt_len + nbt_len bytes.
            let mut slot_id = [0u8; 2];
            src.read_exact(&mut slot_id).await?;
            out.put_slice(&slot_id);
            let item = i16::from_be_bytes(slot_id);
            if item != -1 {
                let mut count_dmg = [0u8; 3];
                src.read_exact(&mut count_dmg).await?;
                out.put_slice(&count_dmg);
                let mut nbt_len_buf = [0u8; 2];
                src.read_exact(&mut nbt_len_buf).await?;
                out.put_slice(&nbt_len_buf);
                let nbt_len = i16::from_be_bytes(nbt_len_buf).max(0) as usize;
                if nbt_len > 0 {
                    let mut nbt = vec![0u8; nbt_len];
                    src.read_exact(&mut nbt).await?;
                    out.put_slice(&nbt);
                }
            }
            let mut tail = [0u8; 3];
            src.read_exact(&mut tail).await?;
            out.put_slice(&tail);
        },
        0x66 => {
            // ClickWindow: [u8 win][i16 slot][i8 button][i16 action]
            // [i8 mode][Slot].
            let mut head = [0u8; 1 + 2 + 1 + 2 + 1];
            src.read_exact(&mut head).await?;
            out.put_slice(&head);
            let mut slot_id = [0u8; 2];
            src.read_exact(&mut slot_id).await?;
            out.put_slice(&slot_id);
            let item = i16::from_be_bytes(slot_id);
            if item != -1 {
                let mut count_dmg = [0u8; 3];
                src.read_exact(&mut count_dmg).await?;
                out.put_slice(&count_dmg);
                let mut nbt_len_buf = [0u8; 2];
                src.read_exact(&mut nbt_len_buf).await?;
                out.put_slice(&nbt_len_buf);
                let nbt_len = i16::from_be_bytes(nbt_len_buf).max(0) as usize;
                if nbt_len > 0 {
                    let mut nbt = vec![0u8; nbt_len];
                    src.read_exact(&mut nbt).await?;
                    out.put_slice(&nbt);
                }
            }
        },
        0x82 => {
            // UpdateSign: [i32 x][i16 y][i32 z][4 × UCS-2 line]
            let mut head = [0u8; 4 + 2 + 4];
            src.read_exact(&mut head).await?;
            out.put_slice(&head);
            for _ in 0..4 {
                let _ = read_ucs2_into(src, &mut out).await?;
            }
        },
        0xCC => {
            // LocaleAndViewDistance: [UCS-2 locale][i8 viewDist][i8 chatFlags][i8 diff][bool showCape]
            let _ = read_ucs2_into(src, &mut out).await?;
            let mut tail = [0u8; 4];
            src.read_exact(&mut tail).await?;
            out.put_slice(&tail);
        },
        0xFA => {
            // PluginMessage: [UCS-2 channel][i16 data_len][bytes data]
            let _ = read_ucs2_into(src, &mut out).await?;
            let mut len_buf = [0u8; 2];
            src.read_exact(&mut len_buf).await?;
            out.put_slice(&len_buf);
            let len = i16::from_be_bytes(len_buf).max(0) as usize;
            if len > 0 {
                let mut data = vec![0u8; len];
                src.read_exact(&mut data).await?;
                out.put_slice(&data);
            }
        },
        0xFF => {
            // Disconnect: [UCS-2 reason]
            let _ = read_ucs2_into(src, &mut out).await?;
        },
        _ => {
            return Err(ConnectionError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown pre-netty packet id 0x{:02X}", id),
            )));
        },
    }

    Ok(out.freeze())
}

/// Read a u16-BE-length-prefixed UCS-2 string from `src` and append
/// the raw `[u16 len][len×u16 chars]` bytes to `out`. Returns the
/// number of source bytes consumed for the caller's debugging.
async fn read_ucs2_into<R: AsyncReadExt + Unpin>(
    src: &mut R,
    out: &mut BytesMut,
) -> Result<usize, ConnectionError> {
    use bytes::BufMut;
    let mut len_buf = [0u8; 2];
    src.read_exact(&mut len_buf).await?;
    out.put_slice(&len_buf);
    let char_count = u16::from_be_bytes(len_buf) as usize;
    let mut chars = vec![0u8; char_count * 2];
    src.read_exact(&mut chars).await?;
    out.put_slice(&chars);
    Ok(2 + char_count * 2)
}

/// Write a single typed play packet, choosing the correct framing for the
/// negotiated protocol version automatically.
///
/// * **Pre-netty (1.6.x):** raw bytes with no length prefix and no
///   compression. The packet id byte is prepended to the body and the whole
///   thing is handed to [`write_legacy_bytes`].
/// * **Modern (1.7+):** the packet id is varint-encoded and prepended to the
///   body, then the combined payload is varint-length-framed with optional
///   zlib compression via [`write_packet`].
///
/// `pid` must already be resolved by `PacketId::packet_id`. `body` is the
/// encoded packet body — everything *after* the id. The sentinel `0xFF`
/// (packet absent for this version) must be filtered out by the caller before
/// reaching here; this function does not check for it.
pub async fn write_typed_packet<W: AsyncWriteExt + Unpin>(
    dst: &mut W,
    pid: u8,
    body: &[u8],
    protocol_version: u32,
    compression_threshold: i32,
) -> Result<(), ConnectionError> {
    if is_pre_netty_proto(protocol_version) {
        // Pre-netty: one raw id byte followed by the body verbatim, no
        // varint framing, no compression.
        let mut raw = GLOBAL_BUFFER_POOL.acquire(1 + body.len());
        raw.put_u8(pid);
        raw.put_slice(body);
        let result = write_legacy_bytes(dst, &raw).await;
        GLOBAL_BUFFER_POOL.release(raw);
        result
    } else {
        // Modern: varint-encode the id, append the body, then hand the
        // combined payload to write_packet which applies framing and
        // optional zlib compression.
        let mut p = GLOBAL_BUFFER_POOL.acquire(5 + body.len());
        VarInt(pid as i32)
            .encode(&mut p)
            .expect("VarInt encode into BytesMut never fails");
        p.put_slice(body);
        let result = write_packet(dst, &p, compression_threshold).await;
        GLOBAL_BUFFER_POOL.release(p);
        result
    }
}

pub async fn read_varint<R: AsyncReadExt + Unpin>(src: &mut R) -> Result<i32, ConnectionError> {
    let mut result: u32 = 0;
    for i in 0..5 {
        let byte = src.read_u8().await?;
        result |= ((byte & 0x7F) as u32) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(result as i32);
        }
    }
    Err(ConnectionError::Protocol(ProtocolError::VarIntOverflow(5)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_uncompressed() {
        let raw = b"\x00hello world";
        let frame = encode_packet(raw, NO_COMPRESSION);

        let mut cur = frame.freeze();
        let len = VarInt::decode(&mut cur).unwrap().0 as usize;
        assert_eq!(len, raw.len());
        assert_eq!(cur.as_ref(), raw);
    }

    #[tokio::test]
    async fn read_write_roundtrip_uncompressed() {
        let raw = b"\x17some packet body".to_vec();
        let frame = encode_packet(&raw, NO_COMPRESSION);
        let mut src = std::io::Cursor::new(frame.to_vec());
        let got = read_packet(&mut src, NO_COMPRESSION).await.unwrap();
        assert_eq!(got.as_ref(), raw.as_slice());
    }

    #[tokio::test]
    async fn read_write_roundtrip_compressed_large() {
        let raw: Vec<u8> = (0..1000u32).map(|i| (i % 7) as u8).collect();
        let frame = encode_packet(&raw, 256);
        let mut src = std::io::Cursor::new(frame.to_vec());
        let got = read_packet(&mut src, 256).await.unwrap();
        assert_eq!(got.as_ref(), raw.as_slice());
    }

    #[tokio::test]
    async fn read_write_roundtrip_compressed_below_threshold() {
        let raw = b"\x10tiny".to_vec();
        let frame = encode_packet(&raw, 256);

        let mut cur = frame.clone().freeze();
        let _frame_len = VarInt::decode(&mut cur).unwrap();
        let data_len = VarInt::decode(&mut cur).unwrap().0;
        assert_eq!(data_len, 0);

        let mut src = std::io::Cursor::new(frame.to_vec());
        let got = read_packet(&mut src, 256).await.unwrap();
        assert_eq!(got.as_ref(), raw.as_slice());
    }

    /// write_typed_packet (modern path) must produce a frame that
    /// read_packet can decode back to the original pid+body.
    #[tokio::test]
    async fn write_typed_packet_modern_roundtrip() {
        let pid: u8 = 0x26;
        let body = b"hello limbo";
        // proto 47 = 1.8, definitely modern
        let mut buf = Vec::new();
        write_typed_packet(&mut buf, pid, body, 47, NO_COMPRESSION)
            .await
            .unwrap();

        let mut src = std::io::Cursor::new(buf);
        let frame = read_packet(&mut src, NO_COMPRESSION).await.unwrap();
        // First byte(s) of frame are the varint-encoded pid.
        let mut cur = frame;
        let got_pid = VarInt::decode(&mut cur).unwrap().0 as u8;
        assert_eq!(got_pid, pid);
        assert_eq!(cur.as_ref(), body);
    }

    /// write_typed_packet (pre-netty path) must produce a raw id byte
    /// followed by the body with no framing wrapper.
    #[tokio::test]
    async fn write_typed_packet_pre_netty_roundtrip() {
        let pid: u8 = 0x01;
        let body = b"pre-netty body";
        // proto 78 = 1.6.4, pre-netty
        let mut buf = Vec::new();
        write_typed_packet(&mut buf, pid, body, 78, NO_COMPRESSION)
            .await
            .unwrap();

        assert_eq!(buf[0], pid);
        assert_eq!(&buf[1..], body);
    }
}
