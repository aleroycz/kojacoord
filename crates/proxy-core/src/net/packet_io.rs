use std::io::{Read, Write};

use bytes::{BufMut, Bytes, BytesMut};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use kojacoord_protocol::{codec::Encode, types::VarInt, Decode, ProtocolError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::buffer_pool::GLOBAL_BUFFER_POOL;
use crate::error::ConnectionError;

pub const NO_COMPRESSION: i32 = -1;

pub const MAX_PACKET_SIZE: usize = 2 * 1024 * 1024;

pub fn encode_frame(body: &[u8]) -> BytesMut {
    let mut out = GLOBAL_BUFFER_POOL.acquire(5 + body.len());
    VarInt(body.len() as i32)
        .encode(&mut out)
        .expect("encoding a VarInt into a BytesMut never fails");
    out.put_slice(body);
    out
}

pub struct ConnectionReader<R> {
    src: R,
    buf: BytesMut,
}

impl<R: AsyncReadExt + Unpin> ConnectionReader<R> {
    pub fn new(src: R) -> Self {
        Self {
            src,
            buf: BytesMut::with_capacity(8192),
        }
    }

    pub fn into_inner(self) -> R {
        self.src
    }

    pub async fn read_packet(&mut self, threshold: i32) -> Result<Bytes, ConnectionError> {
        loop {
            let mut result: u32 = 0;
            let mut shift = 0;
            let mut header_len = 0;
            let mut valid = false;

            for i in 0..self.buf.len() {
                let byte = self.buf[i];
                result |= ((byte & 0x7F) as u32) << shift;
                shift += 7;
                header_len += 1;
                if byte & 0x80 == 0 {
                    valid = true;
                    break;
                }
                if i == 4 {
                    return Err(ConnectionError::Protocol(ProtocolError::VarIntOverflow(5)));
                }
            }

            if valid {
                let packet_len = result as usize;
                if packet_len > MAX_PACKET_SIZE {
                    return Err(ConnectionError::Protocol(ProtocolError::PacketTooLarge(
                        packet_len,
                        MAX_PACKET_SIZE,
                    )));
                }

                let total_len = header_len + packet_len;
                if self.buf.len() >= total_len {
                    // We have the full frame!
                    use bytes::Buf;
                    self.buf.advance(header_len);
                    let body = self.buf.split_to(packet_len).freeze();
                    if threshold >= 0 {
                        return decompress(body);
                    } else {
                        return Ok(body);
                    }
                }
            }

            // Need more data
            if self.buf.capacity() < 8192 {
                self.buf.reserve(8192);
            }
            if self.src.read_buf(&mut self.buf).await? == 0 {
                return Err(ConnectionError::Closed);
            }
        }
    }
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
    ZlibDecoder::new(cursor.as_ref())
        .read_exact(&mut out)
        .map_err(ConnectionError::Io)?;
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
}
