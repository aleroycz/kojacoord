use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::codec::{Decode, Encode, PacketId};
use crate::error::ProtocolError;
use crate::types::VarInt;

pub use clientbound::{
    ClientboundEncryptionRequest, ClientboundLoginDisconnect, ClientboundLoginSuccess,
};
pub use serverbound::{ServerboundEncryptionResponse, ServerboundLoginStart};

mod clientbound {
    use super::*;

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
            let bytes = self.reason.as_bytes();
            VarInt(bytes.len() as i32).encode(dst)?;
            dst.put_slice(bytes);
            Ok(())
        }
    }

    impl Decode for ClientboundLoginDisconnect {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            let len = VarInt::decode(src)?.0 as usize;
            if src.remaining() < len {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing bytes for ClientboundLoginDisconnect reason",
                )));
            }
            let mut buf = vec![0u8; len];
            src.copy_to_slice(&mut buf);
            let reason = String::from_utf8(buf).map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid UTF-8 in ClientboundLoginDisconnect reason",
                ))
            })?;
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

    // Per https://minecraft.wiki/w/Java_Edition_protocol/Packets#Encryption_Request:
    // 1.7.x carried over the pre-netty Short(i16)-prefix for the public_key and
    // verify_token byte arrays. Mojang only switched these to VarInt in 1.8.
    // server_id is still a VarInt-prefixed UTF-8 String in 1.7.x.
    impl Encode for ClientboundEncryptionRequest {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            let id_bytes = self.server_id.as_bytes();
            VarInt(id_bytes.len() as i32).encode(dst)?;
            dst.put_slice(id_bytes);

            if self.public_key.len() > i16::MAX as usize {
                return Err(ProtocolError::UnexpectedEof);
            }
            dst.put_i16(self.public_key.len() as i16);
            dst.put_slice(&self.public_key);

            if self.verify_token.len() > i16::MAX as usize {
                return Err(ProtocolError::UnexpectedEof);
            }
            dst.put_i16(self.verify_token.len() as i16);
            dst.put_slice(&self.verify_token);

            Ok(())
        }
    }

    impl Decode for ClientboundEncryptionRequest {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            let id_len = VarInt::decode(src)?.0 as usize;
            if src.remaining() < id_len {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing bytes for ClientboundEncryptionRequest server_id",
                )));
            }
            let mut id_bytes = vec![0u8; id_len];
            src.copy_to_slice(&mut id_bytes);
            let server_id = String::from_utf8(id_bytes).map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid UTF-8 in ClientboundEncryptionRequest server_id",
                ))
            })?;

            if src.remaining() < 2 {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing Short length for ClientboundEncryptionRequest public_key",
                )));
            }
            let raw_key_len = src.get_i16();
            if raw_key_len < 0 {
                return Err(ProtocolError::UnexpectedEof);
            }
            let key_len = raw_key_len as usize;
            if src.remaining() < key_len {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing bytes for ClientboundEncryptionRequest public_key",
                )));
            }
            let mut public_key = vec![0u8; key_len];
            src.copy_to_slice(&mut public_key);

            if src.remaining() < 2 {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing Short length for ClientboundEncryptionRequest verify_token",
                )));
            }
            let raw_tok_len = src.get_i16();
            if raw_tok_len < 0 {
                return Err(ProtocolError::UnexpectedEof);
            }
            let tok_len = raw_tok_len as usize;
            if src.remaining() < tok_len {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing bytes for ClientboundEncryptionRequest verify_token",
                )));
            }
            let mut verify_token = vec![0u8; tok_len];
            src.copy_to_slice(&mut verify_token);

            Ok(Self {
                server_id,
                public_key,
                verify_token,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundLoginSuccess {
        pub uuid: uuid::Uuid,
        pub username: String,
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

            let name_bytes = self.username.as_bytes();
            VarInt(name_bytes.len() as i32).encode(dst)?;
            dst.put_slice(name_bytes);

            Ok(())
        }
    }

    impl Decode for ClientboundLoginSuccess {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            let uuid_len = VarInt::decode(src)?.0 as usize;
            if src.remaining() < uuid_len {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing bytes for ClientboundLoginSuccess uuid",
                )));
            }
            let mut uuid_bytes = vec![0u8; uuid_len];
            src.copy_to_slice(&mut uuid_bytes);
            let uuid_str = String::from_utf8(uuid_bytes).map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid UTF-8 in ClientboundLoginSuccess uuid",
                ))
            })?;
            let uuid = uuid::Uuid::parse_str(&uuid_str).map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid UUID in ClientboundLoginSuccess",
                ))
            })?;

            let name_len = VarInt::decode(src)?.0 as usize;
            if src.remaining() < name_len {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing bytes for ClientboundLoginSuccess username",
                )));
            }
            let mut name_bytes = vec![0u8; name_len];
            src.copy_to_slice(&mut name_bytes);
            let username = String::from_utf8(name_bytes).map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid UTF-8 in ClientboundLoginSuccess username",
                ))
            })?;

            Ok(Self { uuid, username })
        }
    }
}

mod serverbound {
    use super::*;

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
            let bytes = self.username.as_bytes();
            VarInt(bytes.len() as i32).encode(dst)?;
            dst.put_slice(bytes);
            Ok(())
        }
    }

    impl Decode for ServerboundLoginStart {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            let len = VarInt::decode(src)?.0 as usize;
            if src.remaining() < len {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing bytes for ServerboundLoginStart username",
                )));
            }
            let mut buf = vec![0u8; len];
            src.copy_to_slice(&mut buf);
            let username = String::from_utf8(buf).map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid UTF-8 in ServerboundLoginStart username",
                ))
            })?;
            Ok(Self { username })
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
            if self.shared_secret.len() > i16::MAX as usize {
                return Err(ProtocolError::UnexpectedEof);
            }
            dst.put_i16(self.shared_secret.len() as i16);
            dst.put_slice(&self.shared_secret);

            if self.verify_token.len() > i16::MAX as usize {
                return Err(ProtocolError::UnexpectedEof);
            }
            dst.put_i16(self.verify_token.len() as i16);
            dst.put_slice(&self.verify_token);

            Ok(())
        }
    }

    impl Decode for ServerboundEncryptionResponse {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            if src.remaining() < 2 {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing Short length for ServerboundEncryptionResponse shared_secret",
                )));
            }
            let raw_ss_len = src.get_i16();
            if raw_ss_len < 0 {
                return Err(ProtocolError::UnexpectedEof);
            }
            let ss_len = raw_ss_len as usize;
            if src.remaining() < ss_len {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing bytes for ServerboundEncryptionResponse shared_secret",
                )));
            }
            let mut shared_secret = vec![0u8; ss_len];
            src.copy_to_slice(&mut shared_secret);

            if src.remaining() < 2 {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing Short length for ServerboundEncryptionResponse verify_token",
                )));
            }
            let raw_vt_len = src.get_i16();
            if raw_vt_len < 0 {
                return Err(ProtocolError::UnexpectedEof);
            }
            let vt_len = raw_vt_len as usize;
            if src.remaining() < vt_len {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing bytes for ServerboundEncryptionResponse verify_token",
                )));
            }
            let mut verify_token = vec![0u8; vt_len];
            src.copy_to_slice(&mut verify_token);

            Ok(Self {
                shared_secret,
                verify_token,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_disconnect_roundtrip() {
        let p = ClientboundLoginDisconnect {
            reason: r#"{"text":"You are banned."}"#.to_string(),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        assert_eq!(ClientboundLoginDisconnect::decode(&mut b).unwrap(), p);
    }

    #[test]
    fn encryption_request_roundtrip() {
        let p = ClientboundEncryptionRequest {
            server_id: String::new(),
            public_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
            verify_token: vec![0x01, 0x02, 0x03, 0x04],
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
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        let d = ClientboundLoginSuccess::decode(&mut b).unwrap();
        assert_eq!(d.uuid, p.uuid);
        assert_eq!(d.username, p.username);
    }

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
    fn encryption_response_roundtrip() {
        let p = ServerboundEncryptionResponse {
            shared_secret: vec![0u8; 128],
            verify_token: vec![0xAA; 128],
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut b = buf.freeze();
        assert_eq!(ServerboundEncryptionResponse::decode(&mut b).unwrap(), p);
    }

    #[test]
    fn packet_ids_are_correct() {
        assert_eq!(ClientboundLoginDisconnect::packet_id(5), 0x00);
        assert_eq!(ClientboundEncryptionRequest::packet_id(5), 0x01);
        assert_eq!(ClientboundLoginSuccess::packet_id(5), 0x02);

        assert_eq!(ServerboundLoginStart::packet_id(5), 0x00);
        assert_eq!(ServerboundEncryptionResponse::packet_id(5), 0x01);
    }
}
