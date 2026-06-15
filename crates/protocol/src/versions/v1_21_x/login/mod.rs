use bytes::{Buf, Bytes, BytesMut};

use crate::codec::{decode_byte_array, encode_byte_array, Decode, Encode, PacketId};
use crate::error::ProtocolError;
use crate::types::VarInt;

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundLoginStart {
    pub username: String,
    pub uuid: uuid::Uuid,
}

impl PacketId for ServerboundLoginStart {
    fn packet_id(_ver: u32) -> u8 {
        0x00
    }
}

impl Encode for ServerboundLoginStart {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.username.encode(dst)?;
        self.uuid.encode(dst)
    }
}

impl Decode for ServerboundLoginStart {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let username = String::decode(src)?;
        let uuid = uuid::Uuid::decode(src)?;
        Ok(Self { username, uuid })
    }
}

#[derive(Debug, Clone, PartialEq)]
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
        self.reason.encode(dst)
    }
}

impl Decode for ClientboundLoginDisconnect {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            reason: String::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundEncryptionRequest {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: Vec<u8>,
    /// Always present from 1.20.5 (proto 766) onward, but kept as
    /// `Option<bool>` so the call sites match the v1_20_x signature.
    /// Pass `Some(true)` for any real 1.21 client.
    pub should_authenticate: Option<bool>,
}

impl PacketId for ClientboundEncryptionRequest {
    fn packet_id(_ver: u32) -> u8 {
        0x01
    }
}

impl Encode for ClientboundEncryptionRequest {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.server_id.encode(dst)?;
        encode_byte_array(&self.public_key, dst)?;
        encode_byte_array(&self.verify_token, dst)?;
        if let Some(flag) = self.should_authenticate {
            flag.encode(dst)?;
        }
        Ok(())
    }
}

impl Decode for ClientboundEncryptionRequest {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let server_id = String::decode(src)?;
        let public_key = decode_byte_array(src)?;
        let verify_token = decode_byte_array(src)?;
        let should_authenticate = if src.is_empty() {
            None
        } else {
            Some(bool::decode(src)?)
        };
        Ok(Self {
            server_id,
            public_key,
            verify_token,
            should_authenticate,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProfileProperty {
    pub name: String,

    pub value: String,

    pub signature: Option<String>,
}

impl Encode for ProfileProperty {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.name.encode(dst)?;
        self.value.encode(dst)?;
        self.signature.encode(dst)
    }
}

impl Decode for ProfileProperty {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let name = String::decode(src)?;
        let value = String::decode(src)?;
        let signature = Option::<String>::decode(src)?;
        Ok(Self {
            name,
            value,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundLoginSuccess {
    pub uuid: uuid::Uuid,
    pub username: String,
    pub properties: Vec<ProfileProperty>,
    /// `strict_error_handling` was added in 1.21 (proto 767) and
    /// dropped again in 1.21.4 (proto 769). `None` ⇒ don't emit the
    /// trailing byte.
    pub strict_error_handling: Option<bool>,
}

impl PacketId for ClientboundLoginSuccess {
    fn packet_id(_ver: u32) -> u8 {
        0x02
    }
}

impl Encode for ClientboundLoginSuccess {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        let (hi, lo) = self.uuid.as_u64_pair();
        (hi as i64).encode(dst)?;
        (lo as i64).encode(dst)?;
        self.username.encode(dst)?;
        self.properties.encode(dst)?;
        if let Some(flag) = self.strict_error_handling {
            flag.encode(dst)?;
        }
        Ok(())
    }
}

impl Decode for ClientboundLoginSuccess {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let hi = i64::decode(src)? as u64;
        let lo = i64::decode(src)? as u64;
        let uuid = uuid::Uuid::from_u64_pair(hi, lo);
        let username = String::decode(src)?;
        let properties = Vec::<ProfileProperty>::decode(src)?;
        let strict_error_handling = if src.is_empty() {
            None
        } else {
            Some(bool::decode(src)?)
        };
        Ok(Self {
            uuid,
            username,
            properties,
            strict_error_handling,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundSetCompression {
    pub threshold: VarInt,
}

impl PacketId for ClientboundSetCompression {
    fn packet_id(_ver: u32) -> u8 {
        0x03
    }
}

impl Encode for ClientboundSetCompression {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.threshold.encode(dst)
    }
}

impl Decode for ClientboundSetCompression {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            threshold: VarInt::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundLoginPluginRequest {
    pub message_id: VarInt,

    pub channel: String,

    pub data: Vec<u8>,
}

impl PacketId for ClientboundLoginPluginRequest {
    fn packet_id(_ver: u32) -> u8 {
        0x04
    }
}

impl Encode for ClientboundLoginPluginRequest {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.message_id.encode(dst)?;
        self.channel.encode(dst)?;
        dst.extend_from_slice(&self.data);
        Ok(())
    }
}

impl Decode for ClientboundLoginPluginRequest {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let message_id = VarInt::decode(src)?;
        let channel = String::decode(src)?;
        let data = src.split_to(src.remaining()).to_vec();
        Ok(Self {
            message_id,
            channel,
            data,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundEncryptionResponse {
    pub shared_secret: Vec<u8>,

    pub verify_token: Vec<u8>,
}

impl PacketId for ServerboundEncryptionResponse {
    fn packet_id(_ver: u32) -> u8 {
        0x01
    }
}

impl Encode for ServerboundEncryptionResponse {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        encode_byte_array(&self.shared_secret, dst)?;
        encode_byte_array(&self.verify_token, dst)
    }
}

impl Decode for ServerboundEncryptionResponse {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let shared_secret = decode_byte_array(src)?;
        let verify_token = decode_byte_array(src)?;
        Ok(Self {
            shared_secret,
            verify_token,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundLoginPluginResponse {
    pub message_id: VarInt,

    pub data: Option<Vec<u8>>,
}

impl PacketId for ServerboundLoginPluginResponse {
    fn packet_id(_ver: u32) -> u8 {
        0x02
    }
}

impl Encode for ServerboundLoginPluginResponse {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.message_id.encode(dst)?;
        match &self.data {
            Some(payload) => {
                true.encode(dst)?;
                dst.extend_from_slice(payload);
            },
            None => false.encode(dst)?,
        }
        Ok(())
    }
}

impl Decode for ServerboundLoginPluginResponse {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let message_id = VarInt::decode(src)?;
        let understood = bool::decode(src)?;
        let data = if understood {
            Some(src.split_to(src.remaining()).to_vec())
        } else {
            None
        };
        Ok(Self { message_id, data })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundLoginAcknowledged;

impl PacketId for ServerboundLoginAcknowledged {
    fn packet_id(_ver: u32) -> u8 {
        0x03
    }
}

impl Encode for ServerboundLoginAcknowledged {
    fn encode(&self, _dst: &mut BytesMut) -> Result<(), ProtocolError> {
        Ok(())
    }
}

impl Decode for ServerboundLoginAcknowledged {
    fn decode(_src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_start_roundtrip() {
        let p = ServerboundLoginStart {
            username: "Player1".to_string(),
            uuid: uuid::Uuid::new_v4(),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        assert_eq!(ServerboundLoginStart::decode(&mut b).unwrap(), p);
    }

    #[test]
    fn login_success_empty_properties() {
        let p = ClientboundLoginSuccess {
            uuid: uuid::Uuid::new_v4(),
            username: "Player1".to_string(),
            properties: Vec::new(),
            strict_error_handling: Some(true),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        let d = ClientboundLoginSuccess::decode(&mut b).unwrap();
        assert_eq!(d.uuid, p.uuid);
        assert_eq!(d.username, p.username);
        assert!(d.properties.is_empty());
    }

    #[test]
    fn login_success_with_properties() {
        let p = ClientboundLoginSuccess {
            uuid: uuid::Uuid::new_v4(),
            username: "Player1".to_string(),
            properties: vec![
                ProfileProperty {
                    name: "textures".to_string(),
                    value: "abc123".to_string(),
                    signature: Some("sig".to_string()),
                },
                ProfileProperty {
                    name: "other".to_string(),
                    value: "val".to_string(),
                    signature: None,
                },
            ],
            strict_error_handling: Some(true),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        let d = ClientboundLoginSuccess::decode(&mut b).unwrap();
        assert_eq!(d.uuid, p.uuid);
        assert_eq!(d.properties.len(), 2);
        assert_eq!(d.properties[0].name, "textures");
        assert_eq!(d.properties[1].signature, None);
    }

    #[test]
    fn encryption_request_roundtrip() {
        let p = ClientboundEncryptionRequest {
            server_id: String::new(),
            public_key: vec![0xAB, 0xCD, 0xEF],
            verify_token: vec![1, 2, 3, 4],
            should_authenticate: Some(true),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        assert_eq!(ClientboundEncryptionRequest::decode(&mut b).unwrap(), p);
    }

    #[test]
    fn encryption_response_roundtrip() {
        let p = ServerboundEncryptionResponse {
            shared_secret: vec![0xFF; 16],
            verify_token: vec![0x00; 4],
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        assert_eq!(ServerboundEncryptionResponse::decode(&mut b).unwrap(), p);
    }

    #[test]
    fn set_compression_roundtrip() {
        let p = ClientboundSetCompression {
            threshold: VarInt(512),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        assert_eq!(ClientboundSetCompression::decode(&mut b).unwrap(), p);
    }
}
