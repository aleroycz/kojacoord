use crate::codec::{Decode, Encode, PacketId};
use crate::error::ProtocolError;
use crate::types::VarInt;
use bytes::{Buf, BufMut, Bytes, BytesMut};

fn encode_string(s: &str, dst: &mut BytesMut) -> Result<(), ProtocolError> {
    let bytes = s.as_bytes();
    VarInt(bytes.len() as i32).encode(dst)?;
    dst.put_slice(bytes);
    Ok(())
}

fn decode_string(src: &mut Bytes, context: &'static str) -> Result<String, ProtocolError> {
    let len = VarInt::decode(src)?.0 as usize;
    if src.remaining() < len {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("Missing bytes for {context}"),
        )));
    }
    let mut b = vec![0u8; len];
    src.copy_to_slice(&mut b);
    String::from_utf8(b).map_err(|_| {
        ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid UTF-8 in {context}"),
        ))
    })
}

fn encode_byte_array(data: &[u8], dst: &mut BytesMut) -> Result<(), ProtocolError> {
    VarInt(data.len() as i32).encode(dst)?;
    dst.put_slice(data);
    Ok(())
}

fn decode_byte_array(src: &mut Bytes, context: &'static str) -> Result<Vec<u8>, ProtocolError> {
    let len = VarInt::decode(src)?.0 as usize;
    if src.remaining() < len {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("Missing bytes for {context}"),
        )));
    }
    let mut b = vec![0u8; len];
    src.copy_to_slice(&mut b);
    Ok(b)
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundLoginStart {
    pub username: String,
}

impl PacketId for ServerboundLoginStart {
    fn packet_id(_ver: u32) -> u8 {
        0x00
    }
}

impl Encode for ServerboundLoginStart {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        encode_string(&self.username, dst)
    }
}

impl Decode for ServerboundLoginStart {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let username = decode_string(src, "ServerboundLoginStart username")?;
        Ok(Self { username })
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
        encode_string(&self.reason, dst)
    }
}

impl Decode for ClientboundLoginDisconnect {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let reason = decode_string(src, "ClientboundLoginDisconnect reason")?;
        Ok(Self { reason })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundEncryptionRequest {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: Vec<u8>,
}

impl PacketId for ClientboundEncryptionRequest {
    fn packet_id(_ver: u32) -> u8 {
        0x01
    }
}

impl Encode for ClientboundEncryptionRequest {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        let id_bytes = self.server_id.as_bytes();
        VarInt(id_bytes.len() as i32).encode(dst)?;
        dst.put_slice(id_bytes);

        VarInt(self.public_key.len() as i32).encode(dst)?;
        dst.put_slice(&self.public_key);

        VarInt(self.verify_token.len() as i32).encode(dst)?;
        dst.put_slice(&self.verify_token);

        Ok(())
    }
}

impl Decode for ClientboundEncryptionRequest {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let id_len = VarInt::decode(src)?.0 as usize;
        if src.remaining() < id_len {
            return Err(ProtocolError::UnexpectedEof);
        }
        let mut id_bytes = vec![0u8; id_len];
        src.copy_to_slice(&mut id_bytes);
        let server_id = String::from_utf8(id_bytes).map_err(|_| ProtocolError::UnexpectedEof)?;

        let key_len = VarInt::decode(src)?.0 as usize;
        if src.remaining() < key_len {
            return Err(ProtocolError::UnexpectedEof);
        }
        let mut public_key = vec![0u8; key_len];
        src.copy_to_slice(&mut public_key);

        let token_len = VarInt::decode(src)?.0 as usize;
        if src.remaining() < token_len {
            return Err(ProtocolError::UnexpectedEof);
        }
        let mut verify_token = vec![0u8; token_len];
        src.copy_to_slice(&mut verify_token);

        let remaining_trailing_bytes = src.remaining();
        src.advance(remaining_trailing_bytes);

        Ok(Self {
            server_id,
            public_key,
            verify_token,
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
        let shared_secret = decode_byte_array(src, "ServerboundEncryptionResponse shared_secret")?;
        let verify_token = decode_byte_array(src, "ServerboundEncryptionResponse verify_token")?;
        Ok(Self {
            shared_secret,
            verify_token,
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
        encode_string(&self.name, dst)?;
        encode_string(&self.value, dst)?;
        match &self.signature {
            Some(sig) => {
                dst.put_u8(1);
                encode_string(sig, dst)?;
            },
            None => dst.put_u8(0),
        }
        Ok(())
    }
}

impl Decode for ProfileProperty {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let name = decode_string(src, "ProfileProperty name")?;
        let value = decode_string(src, "ProfileProperty value")?;
        if src.remaining() < 1 {
            return Err(ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Missing signature flag in ProfileProperty",
            )));
        }
        let signature = if src.get_u8() != 0 {
            Some(decode_string(src, "ProfileProperty signature")?)
        } else {
            None
        };
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
}

impl PacketId for ClientboundLoginSuccess {
    fn packet_id(_ver: u32) -> u8 {
        0x02
    }
}

impl Encode for ClientboundLoginSuccess {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        let uuid_str = self.uuid.hyphenated().to_string();
        let uuid_bytes = uuid_str.as_bytes();
        VarInt(uuid_bytes.len() as i32).encode(dst)?;
        dst.put_slice(uuid_bytes);

        let user_bytes = self.username.as_bytes();
        VarInt(user_bytes.len() as i32).encode(dst)?;
        dst.put_slice(user_bytes);

        VarInt(self.properties.len() as i32).encode(dst)?;
        for prop in &self.properties {
            prop.encode(dst)?;
        }

        Ok(())
    }
}

impl Decode for ClientboundLoginSuccess {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let uuid_len = VarInt::decode(src)?.0 as usize;
        if src.remaining() < uuid_len {
            return Err(ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Missing bytes for LoginSuccess UUID",
            )));
        }
        let mut uuid_bytes = vec![0u8; uuid_len];
        src.copy_to_slice(&mut uuid_bytes);
        let uuid_str = String::from_utf8(uuid_bytes).map_err(|_| {
            ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid UTF-8 inside LoginSuccess UUID",
            ))
        })?;

        let uuid = uuid::Uuid::parse_str(&uuid_str).map_err(|_| {
            ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid string format for UUID parsing",
            ))
        })?;

        let user_len = VarInt::decode(src)?.0 as usize;
        if src.remaining() < user_len {
            return Err(ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Missing bytes for LoginSuccess Username",
            )));
        }
        let mut user_bytes = vec![0u8; user_len];
        src.copy_to_slice(&mut user_bytes);
        let username = String::from_utf8(user_bytes).map_err(|_| {
            ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid UTF-8 inside LoginSuccess Username",
            ))
        })?;

        let prop_count = VarInt::decode(src)?.0 as usize;
        let mut properties = Vec::with_capacity(prop_count);
        for _ in 0..prop_count {
            properties.push(ProfileProperty::decode(src)?);
        }

        Ok(Self {
            uuid,
            username,
            properties,
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
        let threshold = VarInt::decode(src)?;
        Ok(Self { threshold })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundLoginPluginRequest {
    pub message_id: VarInt,
    pub channel: String,
    pub data: Vec<u8>,
}

impl PacketId for ClientboundLoginPluginRequest {
    fn packet_id(ver: u32) -> u8 {
        if ver == 340 {
            0xFF
        } else {
            0x04
        }
    }
}

impl Encode for ClientboundLoginPluginRequest {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.message_id.encode(dst)?;
        encode_string(&self.channel, dst)?;
        dst.put_slice(&self.data);
        Ok(())
    }
}

impl Decode for ClientboundLoginPluginRequest {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let message_id = VarInt::decode(src)?;
        let channel = decode_string(src, "ClientboundLoginPluginRequest channel")?;
        let remaining = src.remaining();
        let mut data = vec![0u8; remaining];
        src.copy_to_slice(&mut data);
        Ok(Self {
            message_id,
            channel,
            data,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundLoginPluginResponse {
    pub message_id: VarInt,
    pub successful: bool,
    pub data: Option<Vec<u8>>,
}

impl PacketId for ServerboundLoginPluginResponse {
    fn packet_id(ver: u32) -> u8 {
        if ver == 340 {
            0xFF
        } else {
            0x02
        }
    }
}

impl Encode for ServerboundLoginPluginResponse {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.message_id.encode(dst)?;
        dst.put_u8(if self.successful { 1 } else { 0 });
        if self.successful {
            if let Some(ref data) = self.data {
                dst.put_slice(data);
            }
        }
        Ok(())
    }
}

impl Decode for ServerboundLoginPluginResponse {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let message_id = VarInt::decode(src)?;
        if src.remaining() < 1 {
            return Err(ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Missing successful flag in ServerboundLoginPluginResponse",
            )));
        }
        let successful = src.get_u8() != 0;
        let data = if successful && src.remaining() > 0 {
            let mut d = vec![0u8; src.remaining()];
            src.copy_to_slice(&mut d);
            Some(d)
        } else {
            None
        };
        Ok(Self {
            message_id,
            successful,
            data,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerboundLoginAcknowledged;

impl PacketId for ServerboundLoginAcknowledged {
    fn packet_id(ver: u32) -> u8 {
        if ver == 340 {
            0xFF
        } else {
            0x03
        }
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
pub struct AcknowledgeFinishConfiguration;

impl PacketId for AcknowledgeFinishConfiguration {
    fn packet_id(ver: u32) -> u8 {
        if ver == 340 {
            0xFF
        } else {
            0x02
        }
    }
}

impl Encode for AcknowledgeFinishConfiguration {
    fn encode(&self, _dst: &mut BytesMut) -> Result<(), ProtocolError> {
        Ok(())
    }
}

impl Decode for AcknowledgeFinishConfiguration {
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
            username: "Steve".to_string(),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        assert_eq!(ServerboundLoginStart::decode(&mut b).unwrap(), p);
    }

    #[test]
    fn login_disconnect_roundtrip() {
        let p = ClientboundLoginDisconnect {
            reason: "Banned".to_string(),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        assert_eq!(ClientboundLoginDisconnect::decode(&mut b).unwrap(), p);
    }

    #[test]
    fn encryption_roundtrip() {
        let p = ClientboundEncryptionRequest {
            server_id: String::new(),
            public_key: vec![0xDE, 0xAD],
            verify_token: vec![0xBE, 0xEF],
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        assert_eq!(ClientboundEncryptionRequest::decode(&mut b).unwrap(), p);
    }

    #[test]
    fn login_success_roundtrip() {
        let p = ClientboundLoginSuccess {
            uuid: uuid::Uuid::new_v4(),
            username: "Steve".to_string(),
            properties: vec![ProfileProperty {
                name: "textures".to_string(),
                value: "abc123".to_string(),
                signature: Some("sig".to_string()),
            }],
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        let d = ClientboundLoginSuccess::decode(&mut b).unwrap();
        assert_eq!(d.uuid, p.uuid);
        assert_eq!(d.username, p.username);
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

    #[test]
    fn plugin_request_roundtrip() {
        let p = ClientboundLoginPluginRequest {
            message_id: VarInt(1),
            channel: "my:channel".to_string(),
            data: vec![1, 2, 3],
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        assert_eq!(ClientboundLoginPluginRequest::decode(&mut b).unwrap(), p);
    }

    #[test]
    fn plugin_response_roundtrip() {
        let p = ServerboundLoginPluginResponse {
            message_id: VarInt(1),
            successful: true,
            data: Some(vec![0xAB, 0xCD]),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        assert_eq!(ServerboundLoginPluginResponse::decode(&mut b).unwrap(), p);
    }
}
