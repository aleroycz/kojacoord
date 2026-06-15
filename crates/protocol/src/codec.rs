//! Wire-level encoding primitives.
//!
//! Three traits make up the vocabulary every typed packet uses:
//!   - [`Encode`] / [`Decode`] — serialise a value to/from the
//!     Minecraft wire format
//!   - [`PacketId`] — resolve a packet's id at compile time given a
//!     protocol version; backs `connection.write_typed` and
//!     `limbo.send_play_typed`
//!
//! Bounds: [`MAX_PACKET_SIZE`] is the 32 MiB ceiling vanilla enforces
//! on framed packets; [`MAX_STRING_LENGTH`] is the 32k-character cap
//! the protocol places on `String` fields.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::ProtocolError;

/// Hard cap on a single framed packet — 32 MiB. Matches Notchian.
pub const MAX_PACKET_SIZE: usize = 1 << 25;

/// Hard cap on any `String` field, per the protocol spec. Used by the
/// `String::decode` impl to reject oversized payloads from
/// misbehaving clients.
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

/// Version-aware sibling of [`Encode`] for packets whose body shape
/// changes across protocol versions.
///
/// Every type that implements [`Encode`] gets a free [`EncodeVer`] via
/// the blanket impl below — the `ver` parameter is simply ignored. For
/// the small set of structs whose wire shape depends on the protocol
/// (`ClientboundLogin`, `ClientboundRespawn`, `ClientboundPlayerPosition`
/// in 1.21.4+, etc.) we drop the plain `Encode` impl and provide a
/// hand-written `EncodeVer` that branches on `ver`.
pub trait EncodeVer {
    fn encode_ver(&self, ver: u32, dst: &mut BytesMut) -> Result<(), ProtocolError>;
}

/// Version-aware sibling of [`Decode`]. See [`EncodeVer`] for the
/// rationale.
pub trait DecodeVer: Sized {
    fn decode_ver(ver: u32, src: &mut Bytes) -> Result<Self, ProtocolError>;
}

impl<T: Encode> EncodeVer for T {
    fn encode_ver(&self, _ver: u32, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        self.encode(dst)
    }
}

impl<T: Decode> DecodeVer for T {
    fn decode_ver(_ver: u32, src: &mut Bytes) -> Result<Self, ProtocolError> {
        T::decode(src)
    }
}

/// Write `packet_id(ver) || body(ver)` into `dst`. Pair with `read_packet`.
pub fn write_packet<P: PacketId + EncodeVer>(
    ver: u32,
    pkt: &P,
    dst: &mut BytesMut,
) -> Result<(), ProtocolError> {
    use crate::types::VarInt;
    let id = P::packet_id(ver);
    VarInt(id as i32).encode(dst)?;
    pkt.encode_ver(ver, dst)
}

/// Read the body of a packet whose id has already been consumed.
pub fn read_packet<P: PacketId + DecodeVer>(ver: u32, src: &mut Bytes) -> Result<P, ProtocolError> {
    P::decode_ver(ver, src)
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
        let bytes = src.copy_to_bytes(len);
        Ok(String::from_utf8(bytes.to_vec())?)
    }
}

pub fn encode_byte_array(data: &[u8], dst: &mut BytesMut) -> Result<(), ProtocolError> {
    crate::types::VarInt(data.len() as i32).encode(dst)?;
    dst.put_slice(data);
    Ok(())
}

pub fn decode_byte_array(src: &mut Bytes) -> Result<Vec<u8>, ProtocolError> {
    let raw = crate::types::VarInt::decode(src)?.0;
    if raw < 0 {
        return Err(ProtocolError::PacketTooLarge(raw as usize, MAX_PACKET_SIZE));
    }
    let len = raw as usize;
    if len > MAX_PACKET_SIZE {
        return Err(ProtocolError::PacketTooLarge(len, MAX_PACKET_SIZE));
    }
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

const MAX_VEC_LEN: usize = 65536;

impl<T: Decode> Decode for Vec<T> {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let raw = crate::types::VarInt::decode(src)?.0;
        if raw < 0 {
            return Err(ProtocolError::PacketTooLarge(raw as usize, MAX_VEC_LEN));
        }
        let len = raw as usize;
        if len > MAX_VEC_LEN {
            return Err(ProtocolError::PacketTooLarge(len, MAX_VEC_LEN));
        }
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
