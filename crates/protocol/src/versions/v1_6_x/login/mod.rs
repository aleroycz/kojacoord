use crate::codec::{Decode, Encode, PacketId};
use crate::error::ProtocolError;
use bytes::{Bytes, BytesMut};

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

fn encode_legacy_string(s: &str, dst: &mut BytesMut) {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    dst.extend_from_slice(&(utf16.len() as u16).to_be_bytes());
    for ch in &utf16 {
        dst.extend_from_slice(&ch.to_be_bytes());
    }
}

use bytes::Buf;

#[derive(Debug, Clone)]
pub struct HandshakeC2S {
    pub protocol_version: u8,
    pub username: String,
    pub host: String,
    pub port: i32,
}

impl PacketId for HandshakeC2S {
    fn packet_id(_ver: u32) -> u8 {
        0x02
    }
}

impl Encode for HandshakeC2S {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.extend_from_slice(&[self.protocol_version]);
        encode_legacy_string(&self.username, dst);
        encode_legacy_string(&self.host, dst);
        dst.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }
}

impl Decode for HandshakeC2S {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.is_empty() {
            return Err(ProtocolError::UnexpectedEof);
        }
        let protocol_version = src.get_u8();
        let username = decode_legacy_string(src)?;
        let host = decode_legacy_string(src)?;
        if src.remaining() < 4 {
            return Err(ProtocolError::UnexpectedEof);
        }
        let port = src.get_i32();
        Ok(Self {
            protocol_version,
            username,
            host,
            port,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EncryptionKeyRequestS2C {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: Vec<u8>,
}

impl PacketId for EncryptionKeyRequestS2C {
    fn packet_id(_ver: u32) -> u8 {
        0xFD
    }
}

impl Encode for EncryptionKeyRequestS2C {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        encode_legacy_string(&self.server_id, dst);
        dst.extend_from_slice(&(self.public_key.len() as i16).to_be_bytes());
        dst.extend_from_slice(&self.public_key);
        dst.extend_from_slice(&(self.verify_token.len() as i16).to_be_bytes());
        dst.extend_from_slice(&self.verify_token);
        Ok(())
    }
}

impl Decode for EncryptionKeyRequestS2C {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let server_id = decode_legacy_string(src)?;
        if src.remaining() < 2 {
            return Err(ProtocolError::UnexpectedEof);
        }
        let key_len = i16::from_be_bytes([src[0], src[1]]) as usize;
        src.advance(2);
        if src.remaining() < key_len {
            return Err(ProtocolError::UnexpectedEof);
        }
        let public_key = src.copy_to_bytes(key_len).to_vec();
        if src.remaining() < 2 {
            return Err(ProtocolError::UnexpectedEof);
        }
        let tok_len = i16::from_be_bytes([src[0], src[1]]) as usize;
        src.advance(2);
        if src.remaining() < tok_len {
            return Err(ProtocolError::UnexpectedEof);
        }
        let verify_token = src.copy_to_bytes(tok_len).to_vec();
        Ok(Self {
            server_id,
            public_key,
            verify_token,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EncryptionKeyResponseC2S {
    pub shared_secret: Vec<u8>,
    pub verify_token: Vec<u8>,
}

impl PacketId for EncryptionKeyResponseC2S {
    fn packet_id(_ver: u32) -> u8 {
        0xFC
    }
}

impl Encode for EncryptionKeyResponseC2S {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.extend_from_slice(&(self.shared_secret.len() as i16).to_be_bytes());
        dst.extend_from_slice(&self.shared_secret);
        dst.extend_from_slice(&(self.verify_token.len() as i16).to_be_bytes());
        dst.extend_from_slice(&self.verify_token);
        Ok(())
    }
}

impl Decode for EncryptionKeyResponseC2S {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.remaining() < 2 {
            return Err(ProtocolError::UnexpectedEof);
        }
        let ss_len = i16::from_be_bytes([src[0], src[1]]) as usize;
        src.advance(2);
        if src.remaining() < ss_len {
            return Err(ProtocolError::UnexpectedEof);
        }
        let shared_secret = src.copy_to_bytes(ss_len).to_vec();
        if src.remaining() < 2 {
            return Err(ProtocolError::UnexpectedEof);
        }
        let vt_len = i16::from_be_bytes([src[0], src[1]]) as usize;
        src.advance(2);
        if src.remaining() < vt_len {
            return Err(ProtocolError::UnexpectedEof);
        }
        let verify_token = src.copy_to_bytes(vt_len).to_vec();
        Ok(Self {
            shared_secret,
            verify_token,
        })
    }
}

#[derive(Debug, Clone)]
pub struct LoginRequestS2C {
    pub entity_id: i32,
    pub level_type: String,
    pub game_mode: u8,
    pub dimension: i8,
    pub difficulty: u8,
    pub world_height: u8,
    pub max_players: u8,
}

impl PacketId for LoginRequestS2C {
    fn packet_id(_ver: u32) -> u8 {
        0x01
    }
}

impl Encode for LoginRequestS2C {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.extend_from_slice(&self.entity_id.to_be_bytes());
        encode_legacy_string(&self.level_type, dst);
        dst.extend_from_slice(&[
            self.game_mode,
            self.dimension as u8,
            self.difficulty,
            self.world_height,
            self.max_players,
        ]);
        Ok(())
    }
}

impl Decode for LoginRequestS2C {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.remaining() < 4 {
            return Err(ProtocolError::UnexpectedEof);
        }
        let entity_id = src.get_i32();
        let level_type = decode_legacy_string(src)?;
        if src.remaining() < 5 {
            return Err(ProtocolError::UnexpectedEof);
        }
        let game_mode = src.get_u8();
        let dimension = src.get_i8();
        let difficulty = src.get_u8();
        let world_height = src.get_u8();
        let max_players = src.get_u8();
        Ok(Self {
            entity_id,
            level_type,
            game_mode,
            dimension,
            difficulty,
            world_height,
            max_players,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientboundLoginDisconnect {
    pub reason: String,
}

impl PacketId for ClientboundLoginDisconnect {
    fn packet_id(_ver: u32) -> u8 {
        0x00
    }
}

impl Encode for ClientboundLoginDisconnect {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        encode_legacy_string(&self.reason, dst);
        Ok(())
    }
}

impl Decode for ClientboundLoginDisconnect {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            reason: decode_legacy_string(src)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: `LoginRequestS2C` (Packet1Login) wire shape matches
    /// HexaCord `Packet1Login::write`. Encode-then-decode round-trips
    /// and the byte length equals the sum of fields. This is the
    /// pre-netty client's world-entry signal sent by
    /// `connection.rs::send_login_success` for proto 78.
    #[test]
    fn login_request_round_trip() {
        let original = LoginRequestS2C {
            entity_id: 1234,
            level_type: "flat".to_string(),
            game_mode: 3,
            dimension: 0,
            difficulty: 0,
            world_height: 0,
            max_players: 20,
        };
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();

        //   4 (entity_id)
        // + 2 + 4 * 2 (level_type "flat" UCS-2: 2-byte length prefix
        //              + 4 chars × 2 bytes per char)
        // + 1 + 1 + 1 + 1 + 1 (game_mode/dimension/difficulty/world_height/max_players)
        assert_eq!(buf.len(), 4 + 2 + 4 * 2 + 5, "wire size mismatch");

        let mut bytes = buf.freeze();
        let decoded = LoginRequestS2C::decode(&mut bytes).unwrap();
        assert_eq!(decoded.entity_id, original.entity_id);
        assert_eq!(decoded.level_type, original.level_type);
        assert_eq!(decoded.game_mode, original.game_mode);
        assert_eq!(decoded.dimension, original.dimension);
        assert_eq!(decoded.difficulty, original.difficulty);
        assert_eq!(decoded.world_height, original.world_height);
        assert_eq!(decoded.max_players, original.max_players);
        assert_eq!(bytes.remaining(), 0, "every byte consumed");
    }

    /// First 4 bytes of the encoded LoginRequest MUST be entity_id BE,
    /// not the level_type. Catches an encode-order regression.
    #[test]
    fn login_request_entity_id_is_first_field() {
        let pkt = LoginRequestS2C {
            entity_id: 0x42,
            level_type: "flat".to_string(),
            game_mode: 0,
            dimension: 0,
            difficulty: 0,
            world_height: 0,
            max_players: 0,
        };
        let mut buf = BytesMut::new();
        pkt.encode(&mut buf).unwrap();
        assert_eq!(&buf[..4], &[0x00, 0x00, 0x00, 0x42]);
    }
}
