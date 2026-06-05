use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::codec::{Decode, Encode, PacketId};
use crate::error::ProtocolError;
use crate::types::VarInt;

pub use clientbound::{ClientboundPongResponse, ClientboundStatusResponse};
pub use serverbound::{ServerboundPingRequest, ServerboundStatusRequest};

pub const PROTOCOL_VERSION: u32 = 47;

mod serverbound {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    pub struct ServerboundStatusRequest;

    impl PacketId for ServerboundStatusRequest {
        fn packet_id(_ver: u32) -> u8 {
            0x00
        }
    }

    impl Encode for ServerboundStatusRequest {
        fn encode(&self, _dst: &mut BytesMut) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    impl Decode for ServerboundStatusRequest {
        fn decode(_src: &mut Bytes) -> Result<Self, ProtocolError> {
            Ok(Self)
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ServerboundPingRequest {
        pub payload: i64,
    }

    impl PacketId for ServerboundPingRequest {
        fn packet_id(_ver: u32) -> u8 {
            0x01
        }
    }

    impl Encode for ServerboundPingRequest {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            dst.put_i64(self.payload);
            Ok(())
        }
    }

    impl Decode for ServerboundPingRequest {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            Ok(Self {
                payload: src.get_i64(),
            })
        }
    }
}

mod clientbound {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundStatusResponse {
        pub json_response: String,
    }

    impl PacketId for ClientboundStatusResponse {
        fn packet_id(_ver: u32) -> u8 {
            0x00
        }
    }

    impl Encode for ClientboundStatusResponse {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            let json_bytes = self.json_response.as_bytes();
            VarInt(json_bytes.len() as i32).encode(dst)?;
            dst.put_slice(json_bytes);
            Ok(())
        }
    }

    impl Decode for ClientboundStatusResponse {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            let json_len = VarInt::decode(src)?.0 as usize;

            if src.remaining() < json_len {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing bytes while reading ClientboundStatusResponse JSON payload",
                )));
            }

            let mut json_bytes = vec![0u8; json_len];
            src.copy_to_slice(&mut json_bytes);

            let json_response = String::from_utf8(json_bytes).map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid UTF-8 string in ClientboundStatusResponse",
                ))
            })?;

            Ok(Self { json_response })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundPongResponse {
        pub payload: i64,
    }

    impl PacketId for ClientboundPongResponse {
        fn packet_id(_er: u32) -> u8 {
            0x01
        }
    }

    impl Encode for ClientboundPongResponse {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            dst.put_i64(self.payload);
            Ok(())
        }
    }

    impl Decode for ClientboundPongResponse {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            if src.remaining() < 8 {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing bytes for ClientboundPongResponse payload",
                )));
            }
            Ok(Self {
                payload: src.get_i64(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_request_roundtrip() {
        let mut buf = BytesMut::new();
        ServerboundStatusRequest.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        let _ = ServerboundStatusRequest::decode(&mut bytes).unwrap();
    }

    #[test]
    fn status_response_roundtrip() {
        let p = ClientboundStatusResponse {
            json_response: r#"{"version":{"name":"1.8","protocol":47},"players":{"max":20,"online":0},"description":{"text":"A Minecraft 1.8 server"}}"#.to_string(),
        };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        assert_eq!(ClientboundStatusResponse::decode(&mut bytes).unwrap(), p);
    }

    #[test]
    fn ping_roundtrip() {
        let p = ServerboundPingRequest { payload: 123456789 };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        assert_eq!(ServerboundPingRequest::decode(&mut bytes).unwrap(), p);
    }

    #[test]
    fn pong_roundtrip() {
        let p = ClientboundPongResponse { payload: -99 };
        let mut buf = BytesMut::new();
        p.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        assert_eq!(ClientboundPongResponse::decode(&mut bytes).unwrap(), p);
    }

    #[test]
    fn packet_ids_are_correct_for_1_8() {
        assert_eq!(ServerboundStatusRequest::packet_id(PROTOCOL_VERSION), 0x00);
        assert_eq!(ServerboundPingRequest::packet_id(PROTOCOL_VERSION), 0x01);
        assert_eq!(ClientboundStatusResponse::packet_id(PROTOCOL_VERSION), 0x00);
        assert_eq!(ClientboundPongResponse::packet_id(PROTOCOL_VERSION), 0x01);
    }
}
