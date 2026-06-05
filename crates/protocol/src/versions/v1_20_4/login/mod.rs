use bytes::{Bytes, BytesMut};

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
            Some(src.split_to(src.len()).to_vec())
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

    pub should_authenticate: bool,
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
        self.should_authenticate.encode(dst)
    }
}

impl Decode for ClientboundEncryptionRequest {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let server_id = String::decode(src)?;
        let public_key = decode_byte_array(src)?;
        let verify_token = decode_byte_array(src)?;
        let should_authenticate = bool::decode(src)?;
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

    pub strict_error_handling: bool,
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
        self.strict_error_handling.encode(dst)
    }
}

impl Decode for ClientboundLoginSuccess {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let hi = i64::decode(src)? as u64;
        let lo = i64::decode(src)? as u64;
        let uuid = uuid::Uuid::from_u64_pair(hi, lo);
        let username = String::decode(src)?;
        let properties = Vec::<ProfileProperty>::decode(src)?;
        let strict_error_handling = bool::decode(src)?;
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
        let data = src.split_to(src.len()).to_vec();
        Ok(Self {
            message_id,
            channel,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_start_roundtrip() {
        let p = ServerboundLoginStart {
            username: "Player".to_string(),
            uuid: uuid::Uuid::new_v4(),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(ServerboundLoginStart::decode(&mut buf.freeze()).unwrap(), p);
    }

    #[test]
    fn encryption_response_roundtrip() {
        let p = ServerboundEncryptionResponse {
            shared_secret: vec![0xAA; 16],
            verify_token: vec![0xBB; 4],
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ServerboundEncryptionResponse::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn login_plugin_response_understood() {
        let p = ServerboundLoginPluginResponse {
            message_id: VarInt(1),
            data: Some(vec![0x01, 0x02]),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ServerboundLoginPluginResponse::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn login_plugin_response_not_understood() {
        let p = ServerboundLoginPluginResponse {
            message_id: VarInt(1),
            data: None,
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ServerboundLoginPluginResponse::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn login_acknowledged_roundtrip() {
        let p = ServerboundLoginAcknowledged;
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ServerboundLoginAcknowledged::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn login_disconnect_roundtrip() {
        let p = ClientboundLoginDisconnect {
            reason: r#"{"text":"banned"}"#.to_string(),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ClientboundLoginDisconnect::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn encryption_request_roundtrip() {
        let p = ClientboundEncryptionRequest {
            server_id: String::new(),
            public_key: vec![0x01, 0x02],
            verify_token: vec![0x03, 0x04, 0x05, 0x06],
            should_authenticate: false,
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ClientboundEncryptionRequest::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn login_success_with_strict_error_handling() {
        let p = ClientboundLoginSuccess {
            uuid: uuid::Uuid::new_v4(),
            username: "Player".to_string(),
            properties: vec![ProfileProperty {
                name: "textures".to_string(),
                value: "data".to_string(),
                signature: None,
            }],
            strict_error_handling: true,
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let d = ClientboundLoginSuccess::decode(&mut buf.freeze()).unwrap();
        assert_eq!(d.uuid, p.uuid);
        assert!(d.strict_error_handling);
        assert_eq!(d.properties.len(), 1);
    }

    #[test]
    fn set_compression_roundtrip() {
        let p = ClientboundSetCompression {
            threshold: VarInt(256),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ClientboundSetCompression::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn login_plugin_request_roundtrip() {
        let p = ClientboundLoginPluginRequest {
            message_id: VarInt(42),
            channel: "forge:handshake".to_string(),
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        assert_eq!(
            ClientboundLoginPluginRequest::decode(&mut buf.freeze()).unwrap(),
            p
        );
    }

    #[test]
    fn packet_ids() {
        assert_eq!(ServerboundLoginStart::packet_id(765), 0x00);
        assert_eq!(ServerboundEncryptionResponse::packet_id(765), 0x01);
        assert_eq!(ServerboundLoginPluginResponse::packet_id(765), 0x02);
        assert_eq!(ServerboundLoginAcknowledged::packet_id(765), 0x03);
        assert_eq!(ClientboundLoginDisconnect::packet_id(765), 0x00);
        assert_eq!(ClientboundEncryptionRequest::packet_id(765), 0x01);
        assert_eq!(ClientboundLoginSuccess::packet_id(765), 0x02);
        assert_eq!(ClientboundSetCompression::packet_id(765), 0x03);
        assert_eq!(ClientboundLoginPluginRequest::packet_id(765), 0x04);
    }
}
