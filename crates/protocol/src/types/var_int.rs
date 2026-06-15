//! 32-bit variable-length integer.
//!
//! Minecraft's pervasive integer encoding: 7 bits per byte, MSB set
//! when more bytes follow, two's-complement for negatives (so -1
//! takes the maximum 5 bytes). Used as length prefixes, packet ids,
//! entity ids, and most everything else integer-shaped on the wire.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    codec::{Decode, Encode},
    error::ProtocolError,
};

/// Maximum byte length of a serialized 32-bit VarInt. Used as a sanity
/// cap by the decoder — anything longer is malformed and rejected.
pub const VARINT_MAX_BYTES: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VarInt(pub i32);

impl VarInt {
    pub fn encoded_len(self) -> usize {
        let mut val = self.0 as u32;
        let mut count = 1;
        while val >= 0x80 {
            val >>= 7;
            count += 1;
        }
        count
    }
}

impl Encode for VarInt {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        let mut val = self.0 as u32;
        loop {
            let byte = (val & 0x7F) as u8;
            val >>= 7;
            if val != 0 {
                dst.put_u8(byte | 0x80);
            } else {
                dst.put_u8(byte);
                break;
            }
        }
        Ok(())
    }
}

impl Decode for VarInt {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        let mut result: u32 = 0;
        let mut shift = 0u32;
        let mut bytes_read = 0;

        loop {
            if bytes_read >= VARINT_MAX_BYTES {
                return Err(ProtocolError::VarIntOverflow(bytes_read));
            }
            if src.is_empty() {
                return Err(ProtocolError::UnexpectedEof);
            }
            let byte = src.get_u8();
            bytes_read += 1;
            if bytes_read == VARINT_MAX_BYTES && byte & 0xF0 != 0 {
                return Err(ProtocolError::VarIntOverflow(bytes_read));
            }
            result |= ((byte & 0x7F) as u32) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }

        Ok(VarInt(result as i32))
    }
}

impl From<i32> for VarInt {
    fn from(v: i32) -> Self {
        VarInt(v)
    }
}

impl From<VarInt> for i32 {
    fn from(v: VarInt) -> Self {
        v.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(val: i32) -> i32 {
        let mut buf = BytesMut::new();
        VarInt(val).encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        VarInt::decode(&mut bytes).unwrap().0
    }

    #[test]
    fn roundtrip_zero() {
        assert_eq!(roundtrip(0), 0);
    }

    #[test]
    fn roundtrip_one() {
        assert_eq!(roundtrip(1), 1);
    }

    #[test]
    fn roundtrip_max() {
        assert_eq!(roundtrip(i32::MAX), i32::MAX);
    }

    #[test]
    fn roundtrip_minus_one() {
        assert_eq!(roundtrip(-1), -1);
    }

    #[test]
    fn roundtrip_min() {
        assert_eq!(roundtrip(i32::MIN), i32::MIN);
    }

    #[test]
    fn encoded_len_small() {
        assert_eq!(VarInt(0).encoded_len(), 1);
        assert_eq!(VarInt(127).encoded_len(), 1);
        assert_eq!(VarInt(128).encoded_len(), 2);
        assert_eq!(VarInt(i32::MAX).encoded_len(), 5);
    }

    #[test]
    fn known_encodings() {
        let cases = [
            (0i32, vec![0x00u8]),
            (1, vec![0x01]),
            (2, vec![0x02]),
            (127, vec![0x7F]),
            (128, vec![0x80, 0x01]),
            (255, vec![0xFF, 0x01]),
            (25565, vec![0xDD, 0xC7, 0x01]),
            (2097151, vec![0xFF, 0xFF, 0x7F]),
            (2147483647, vec![0xFF, 0xFF, 0xFF, 0xFF, 0x07]),
            (-1, vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F]),
            (-2147483648, vec![0x80, 0x80, 0x80, 0x80, 0x08]),
        ];

        for (val, expected) in cases {
            let mut buf = BytesMut::new();
            VarInt(val).encode(&mut buf).unwrap();
            assert_eq!(
                buf.as_ref(),
                expected.as_slice(),
                "encoding mismatch for {}",
                val
            );

            let mut bytes = buf.freeze();
            assert_eq!(
                VarInt::decode(&mut bytes).unwrap().0,
                val,
                "decoding mismatch for {:?}",
                expected
            );
        }
    }
}
