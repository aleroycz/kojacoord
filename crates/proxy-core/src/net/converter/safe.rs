use bytes::{Buf, Bytes};
use std::panic::AssertUnwindSafe;

use kojacoord_protocol::codec::Decode;
use kojacoord_protocol::types::{Position, Slot, VarInt};

use super::ConversionResult;

pub fn guard<F>(what: &str, f: F) -> ConversionResult
where
    F: FnOnce() -> ConversionResult,
{
    match std::panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => {
            tracing::error!(target: "converter", packet = what, "converter panicked; dropping packet");
            ConversionResult::Drop
        },
    }
}

pub struct Reader {
    buf: Bytes,
}

#[allow(dead_code)]
impl Reader {
    pub fn new(buf: Bytes) -> Self {
        Self { buf }
    }
    pub fn remaining(&self) -> usize {
        self.buf.remaining()
    }
    pub fn has(&self, n: usize) -> bool {
        self.buf.remaining() >= n
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.has(1).then(|| self.buf.get_u8())
    }
    pub fn i8(&mut self) -> Option<i8> {
        self.has(1).then(|| self.buf.get_i8())
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.has(2).then(|| self.buf.get_u16())
    }
    pub fn i16(&mut self) -> Option<i16> {
        self.has(2).then(|| self.buf.get_i16())
    }
    pub fn i32(&mut self) -> Option<i32> {
        self.has(4).then(|| self.buf.get_i32())
    }
    pub fn i64(&mut self) -> Option<i64> {
        self.has(8).then(|| self.buf.get_i64())
    }
    pub fn f32(&mut self) -> Option<f32> {
        self.has(4).then(|| self.buf.get_f32())
    }
    pub fn f64(&mut self) -> Option<f64> {
        self.has(8).then(|| self.buf.get_f64())
    }
    pub fn varint(&mut self) -> Option<i32> {
        VarInt::decode(&mut self.buf).ok().map(|v| v.0)
    }
    pub fn string(&mut self) -> Option<String> {
        String::decode(&mut self.buf).ok()
    }
    pub fn position(&mut self) -> Option<Position> {
        Position::decode(&mut self.buf).ok()
    }
    pub fn slot(&mut self) -> Option<Slot> {
        Slot::decode(&mut self.buf).ok()
    }
    pub fn take(&mut self, n: usize) -> Option<Bytes> {
        self.has(n).then(|| self.buf.split_to(n))
    }
    pub fn rest(&mut self) -> Bytes {
        self.buf.split_off(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_short_read_is_none() {
        let mut r = Reader::new(Bytes::from_static(&[0x01, 0x02]));
        assert_eq!(r.u8(), Some(0x01));
        assert_eq!(r.i32(), None);
        assert_eq!(r.remaining(), 1);
    }

    #[test]
    fn guard_catches_panic() {
        let r = guard("test", || panic!("boom"));
        assert!(matches!(r, ConversionResult::Drop));
    }
}
