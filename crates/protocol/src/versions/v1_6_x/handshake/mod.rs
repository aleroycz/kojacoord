use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::codec::{Decode, Encode, PacketId};
use crate::error::ProtocolError;

fn decode_legacy_string(src: &mut Bytes) -> Result<String, ProtocolError> {
    if src.len() < 2 {
        return Err(ProtocolError::UnexpectedEof);
    }
    let len = u16::from_be_bytes([src[0], src[1]]) as usize;
    src.advance(2);
    let byte_len = len * 2;
    if src.len() < byte_len {
        return Err(ProtocolError::UnexpectedEof);
    }
    let raw = src.copy_to_bytes(byte_len);
    let chars: Vec<u16> = raw
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&chars).map_err(|_| ProtocolError::UnexpectedEof)
}

fn encode_legacy_string(s: &str, dst: &mut BytesMut) -> Result<(), ProtocolError> {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    if utf16.len() > u16::MAX as usize {
        return Err(ProtocolError::UnexpectedEof);
    }
    dst.extend_from_slice(&(utf16.len() as u16).to_be_bytes());
    for ch in &utf16 {
        dst.extend_from_slice(&ch.to_be_bytes());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundHandshake {
    pub protocol_version: u8,
    pub username: String,
    pub host: String,
    pub port: i32,
}

impl PacketId for ServerboundHandshake {
    fn packet_id(_ver: u32) -> u8 {
        0x02
    }
}

impl Encode for ServerboundHandshake {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_u8(self.protocol_version);
        encode_legacy_string(&self.username, dst)?;
        encode_legacy_string(&self.host, dst)?;
        dst.put_i32(self.port);
        Ok(())
    }
}

impl Decode for ServerboundHandshake {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let protocol_version = src.get_u8();
        let username = decode_legacy_string(src)?;
        let host = decode_legacy_string(src)?;
        let port = src.get_i32();
        Ok(Self {
            protocol_version,
            username,
            host,
            port,
        })
    }
}
