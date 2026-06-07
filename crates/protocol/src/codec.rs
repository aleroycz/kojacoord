use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::ProtocolError;

pub const MAX_PACKET_SIZE: usize = 1 << 25;

pub const MAX_STRING_LENGTH: usize = 32767;

pub trait Encode {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError>;
}

pub trait Decode: Sized {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError>;
}

pub trait PacketId {
    fn packet_id(protocol_version: u32) -> u8;
}

impl Encode for bool {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_u8(*self as u8);
        Ok(())
    }
}

impl Decode for bool {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.is_empty() {
            return Err(ProtocolError::UnexpectedEof);
        }
        Ok(src.get_u8() != 0)
    }
}

impl Encode for u8 {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_u8(*self);
        Ok(())
    }
}

impl Decode for u8 {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.is_empty() {
            return Err(ProtocolError::UnexpectedEof);
        }
        Ok(src.get_u8())
    }
}

impl Encode for i8 {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_i8(*self);
        Ok(())
    }
}

impl Decode for i8 {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.is_empty() {
            return Err(ProtocolError::UnexpectedEof);
        }
        Ok(src.get_i8())
    }
}

impl Encode for i16 {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_i16(*self);
        Ok(())
    }
}

impl Decode for i16 {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.remaining() < 2 {
            return Err(ProtocolError::UnexpectedEof);
        }
        Ok(src.get_i16())
    }
}

impl Encode for u16 {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_u16(*self);
        Ok(())
    }
}

impl Decode for u16 {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.remaining() < 2 {
            return Err(ProtocolError::UnexpectedEof);
        }
        Ok(src.get_u16())
    }
}

impl Encode for i32 {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_i32(*self);
        Ok(())
    }
}

impl Decode for i32 {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.remaining() < 4 {
            return Err(ProtocolError::UnexpectedEof);
        }
        Ok(src.get_i32())
    }
}

impl Encode for u32 {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_u32(*self);
        Ok(())
    }
}

impl Decode for u32 {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.remaining() < 4 {
            return Err(ProtocolError::UnexpectedEof);
        }
        Ok(src.get_u32())
    }
}

impl Encode for i64 {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_i64(*self);
        Ok(())
    }
}

impl Decode for i64 {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.remaining() < 8 {
            return Err(ProtocolError::UnexpectedEof);
        }
        Ok(src.get_i64())
    }
}

impl Encode for u64 {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_u64(*self);
        Ok(())
    }
}

impl Decode for u64 {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.remaining() < 8 {
            return Err(ProtocolError::UnexpectedEof);
        }
        Ok(src.get_u64())
    }
}

impl Encode for f32 {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_f32(*self);
        Ok(())
    }
}

impl Decode for f32 {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.remaining() < 4 {
            return Err(ProtocolError::UnexpectedEof);
        }
        Ok(src.get_f32())
    }
}

impl Encode for f64 {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_f64(*self);
        Ok(())
    }
}

impl Decode for f64 {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.remaining() < 8 {
            return Err(ProtocolError::UnexpectedEof);
        }
        Ok(src.get_f64())
    }
}

impl Encode for String {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        let bytes = self.as_bytes();
        if bytes.len() > MAX_STRING_LENGTH * 3 {
            return Err(ProtocolError::StringTooLong(
                bytes.len(),
                MAX_STRING_LENGTH * 3,
            ));
        }
        crate::types::VarInt(bytes.len() as i32).encode(dst)?;
        dst.put_slice(bytes);
        Ok(())
    }
}

impl Decode for String {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let len = crate::types::VarInt::decode(src)?.0 as usize;
        if len > MAX_STRING_LENGTH * 3 {
            return Err(ProtocolError::StringTooLong(len, MAX_STRING_LENGTH * 3));
        }
        if src.remaining() < len {
            return Err(ProtocolError::UnexpectedEof);
        }

        // Fast path for contiguous chunk
        let chunk = src.chunk();
        if chunk.len() >= len {
            let slice = &chunk[..len];
            if simdutf8::basic::from_utf8(slice).is_err() {
                // Fallback to std to generate the proper FromUtf8Error
                let buf = src.copy_to_bytes(len).to_vec();
                return Ok(String::from_utf8(buf)?);
            }
            // Validated by simdutf8, construct directly
            let s = unsafe { String::from_utf8_unchecked(slice.to_vec()) };
            src.advance(len);
            return Ok(s);
        }

        // Slow path: copy bytes from multiple chunks
        let buf = src.copy_to_bytes(len).to_vec();
        if simdutf8::basic::from_utf8(&buf).is_err() {
            return Ok(String::from_utf8(buf)?);
        }
        Ok(unsafe { String::from_utf8_unchecked(buf) })
    }
}

pub fn encode_byte_array(data: &[u8], dst: &mut BytesMut) -> Result<(), ProtocolError> {
    crate::types::VarInt(data.len() as i32).encode(dst)?;
    dst.put_slice(data);
    Ok(())
}

pub fn decode_byte_array(src: &mut Bytes) -> Result<Vec<u8>, ProtocolError> {
    let len = crate::types::VarInt::decode(src)?.0 as usize;
    if src.remaining() < len {
        return Err(ProtocolError::UnexpectedEof);
    }
    Ok(src.copy_to_bytes(len).to_vec())
}

impl Encode for uuid::Uuid {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_slice(self.as_bytes());
        Ok(())
    }
}

impl Decode for uuid::Uuid {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.remaining() < 16 {
            return Err(ProtocolError::UnexpectedEof);
        }
        let mut buf = [0u8; 16];
        src.copy_to_slice(&mut buf);
        Ok(uuid::Uuid::from_bytes(buf))
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        crate::types::VarInt(self.len() as i32).encode(dst)?;
        for item in self {
            item.encode(dst)?;
        }
        Ok(())
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let len = crate::types::VarInt::decode(src)?.0 as usize;
        let mut out = Vec::with_capacity(len.min(4096));
        for _ in 0..len {
            out.push(T::decode(src)?);
        }
        Ok(out)
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        match self {
            Some(v) => {
                true.encode(dst)?;
                v.encode(dst)
            },
            None => false.encode(dst),
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let present = bool::decode(src)?;
        if present {
            Ok(Some(T::decode(src)?))
        } else {
            Ok(None)
        }
    }
}
