//! Length-prefixed framing handler for the netty pipeline.
//!
//! Same VarInt-prefixed framing the proxy uses on the wire, but
//! exposed via the `ChannelHandler` trait so it can sit in a netty
//! pipeline alongside cipher / compression handlers.

use bytes::{Buf, Bytes, BytesMut};
use kojacoord_protocol::{
    codec::{Decode as _, Encode as _},
    types::VarInt,
};
use tokio_util::codec::{Decoder, Encoder};

const MAX_FRAME: usize = 1 << 21;

pub struct MinecraftFrameCodec {
    cipher: Option<super::cipher::CipherState>,
    /// Number of leading bytes in the read buffer that have already been
    /// decrypted. AES-CFB8 is a stateful stream cipher, so each ciphertext byte
    /// must be decrypted exactly once; without this counter a frame split across
    /// multiple reads would be decrypted twice and desynchronise the keystream.
    decrypted: usize,
}

impl MinecraftFrameCodec {
    pub fn new() -> Self {
        Self {
            cipher: None,
            decrypted: 0,
        }
    }

    pub fn enable_cipher(&mut self, state: super::cipher::CipherState) {
        self.cipher = Some(state);
    }
}

impl Default for MinecraftFrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for MinecraftFrameCodec {
    type Item = Bytes;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Decrypt only the bytes that have arrived since the last call so each
        // ciphertext byte passes through the CFB8 keystream exactly once.
        if let Some(cipher) = &mut self.cipher {
            if self.decrypted < src.len() {
                cipher.decrypt(&mut src.as_mut()[self.decrypted..]);
                self.decrypted = src.len();
            }
        }

        let mut peek = Bytes::copy_from_slice(src.as_ref());
        let len_varint = match VarInt::decode(&mut peek) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        let header_len = src.len() - peek.len();
        if len_varint.0 < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("negative frame length {}", len_varint.0),
            ));
        }

        let payload_len = len_varint.0 as usize;

        if payload_len > MAX_FRAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame size {payload_len} exceeds maximum {MAX_FRAME}"),
            ));
        }

        if src.len() < header_len + payload_len {
            return Ok(None);
        }

        let consumed = header_len + payload_len;
        src.advance(header_len);
        let frame = src.split_to(payload_len).freeze();
        // The bytes we just consumed were already counted as decrypted; keep the
        // counter aligned with the remaining (already-decrypted) buffer contents.
        self.decrypted = self.decrypted.saturating_sub(consumed);
        Ok(Some(frame))
    }
}

impl Encoder<Bytes> for MinecraftFrameCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let start = dst.len();

        let mut header = BytesMut::new();
        VarInt(item.len() as i32)
            .encode(&mut header)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

        dst.extend_from_slice(&header);
        dst.extend_from_slice(&item);

        if let Some(cipher) = &mut self.cipher {
            cipher.encrypt(&mut dst[start..]);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_small() {
        let payload = Bytes::from_static(b"hello minecraft");
        let mut codec = MinecraftFrameCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(payload.clone(), &mut buf).unwrap();

        let decoded = codec
            .decode(&mut buf)
            .unwrap()
            .expect("should have a frame");
        assert_eq!(decoded, payload);
        assert!(buf.is_empty(), "buffer should be fully consumed");
    }

    #[test]
    fn frame_roundtrip_empty_payload() {
        let payload = Bytes::new();
        let mut codec = MinecraftFrameCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(payload.clone(), &mut buf).unwrap();
        let decoded = codec
            .decode(&mut buf)
            .unwrap()
            .expect("should have a frame");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn frame_partial_data_returns_none() {
        let payload = Bytes::from(vec![0xAA; 100]);
        let mut codec = MinecraftFrameCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(payload, &mut buf).unwrap();

        buf.truncate(5);
        let result = MinecraftFrameCodec::new().decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn frame_roundtrip_large() {
        let payload = Bytes::from(vec![0xBB; 1024]);
        let mut codec = MinecraftFrameCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(payload.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, payload);
    }
}
