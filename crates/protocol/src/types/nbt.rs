//! Named Binary Tag — Minecraft's native data format.
//!
//! Two surfaces:
//!   - [`Nbt`] / [`NbtTag`] for full parse/build trees, used by the
//!     dimension-codec builder and friends
//!   - [`skip`] for streaming over a top-level NBT value without
//!     materialising it, used by version converters that need to
//!     skip past an embedded codec without caring about the contents
//!
//! Wire format reference:
//! <https://minecraft.wiki/w/NBT_format>.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;

const MAX_NBT_DEPTH: usize = 512;
const MAX_NBT_ARRAY_LEN: i32 = 1_048_576;

use crate::{
    codec::{Decode, Encode},
    error::ProtocolError,
};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagType {
    End = 0,

    Byte = 1,

    Short = 2,

    Int = 3,

    Long = 4,

    Float = 5,

    Double = 6,

    ByteArray = 7,

    String = 8,

    List = 9,

    Compound = 10,

    IntArray = 11,

    LongArray = 12,
}

impl TagType {
    pub fn from_u8(v: u8) -> Result<Self, ProtocolError> {
        match v {
            0 => Ok(TagType::End),
            1 => Ok(TagType::Byte),
            2 => Ok(TagType::Short),
            3 => Ok(TagType::Int),
            4 => Ok(TagType::Long),
            5 => Ok(TagType::Float),
            6 => Ok(TagType::Double),
            7 => Ok(TagType::ByteArray),
            8 => Ok(TagType::String),
            9 => Ok(TagType::List),
            10 => Ok(TagType::Compound),
            11 => Ok(TagType::IntArray),
            12 => Ok(TagType::LongArray),
            other => Err(ProtocolError::UnknownNbtTag(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum NbtTag {
    End,

    Byte(i8),

    Short(i16),

    Int(i32),

    Long(i64),

    Float(f32),

    Double(f64),

    ByteArray(Vec<i8>),

    String(String),

    List(Vec<NbtTag>),

    Compound(HashMap<String, NbtTag>),

    IntArray(Vec<i32>),

    LongArray(Vec<i64>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Nbt {
    pub name: String,

    pub root: HashMap<String, NbtTag>,
}

impl Nbt {
    pub fn empty(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            root: HashMap::new(),
        }
    }
}

fn read_nbt_string(src: &mut Bytes) -> Result<String, ProtocolError> {
    if src.remaining() < 2 {
        return Err(ProtocolError::UnexpectedEof);
    }
    let len = src.get_u16() as usize;
    if src.remaining() < len {
        return Err(ProtocolError::UnexpectedEof);
    }
    let bytes = src.copy_to_bytes(len);
    Ok(String::from_utf8(bytes.to_vec())?)
}

fn write_nbt_string(s: &str, dst: &mut BytesMut) -> Result<(), ProtocolError> {
    let bytes = s.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(ProtocolError::UnknownNbtTag(0));
    }
    dst.put_u16(bytes.len() as u16);
    dst.put_slice(bytes);
    Ok(())
}

fn read_tag_payload(tag_type: TagType, src: &mut Bytes) -> Result<NbtTag, ProtocolError> {
    read_tag_payload_depth(tag_type, src, 0)
}

fn read_tag_payload_depth(
    tag_type: TagType,
    src: &mut Bytes,
    depth: usize,
) -> Result<NbtTag, ProtocolError> {
    match tag_type {
        TagType::End => Ok(NbtTag::End),
        TagType::Byte => {
            if src.is_empty() {
                return Err(ProtocolError::UnexpectedEof);
            }
            Ok(NbtTag::Byte(src.get_i8()))
        },
        TagType::Short => {
            if src.remaining() < 2 {
                return Err(ProtocolError::UnexpectedEof);
            }
            Ok(NbtTag::Short(src.get_i16()))
        },
        TagType::Int => {
            if src.remaining() < 4 {
                return Err(ProtocolError::UnexpectedEof);
            }
            Ok(NbtTag::Int(src.get_i32()))
        },
        TagType::Long => {
            if src.remaining() < 8 {
                return Err(ProtocolError::UnexpectedEof);
            }
            Ok(NbtTag::Long(src.get_i64()))
        },
        TagType::Float => {
            if src.remaining() < 4 {
                return Err(ProtocolError::UnexpectedEof);
            }
            Ok(NbtTag::Float(src.get_f32()))
        },
        TagType::Double => {
            if src.remaining() < 8 {
                return Err(ProtocolError::UnexpectedEof);
            }
            Ok(NbtTag::Double(src.get_f64()))
        },
        TagType::ByteArray => {
            if src.remaining() < 4 {
                return Err(ProtocolError::UnexpectedEof);
            }
            let raw_len = src.get_i32();
            if !(0..=MAX_NBT_ARRAY_LEN).contains(&raw_len) {
                return Err(ProtocolError::UnknownNbtTag(0));
            }
            let len = raw_len as usize;
            if src.remaining() < len {
                return Err(ProtocolError::UnexpectedEof);
            }
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(src.get_i8());
            }
            Ok(NbtTag::ByteArray(arr))
        },
        TagType::String => Ok(NbtTag::String(read_nbt_string(src)?)),
        TagType::List => {
            if src.is_empty() {
                return Err(ProtocolError::UnexpectedEof);
            }
            let element_type = TagType::from_u8(src.get_u8())?;
            if src.remaining() < 4 {
                return Err(ProtocolError::UnexpectedEof);
            }
            let raw_len = src.get_i32();
            if !(0..=MAX_NBT_ARRAY_LEN).contains(&raw_len) {
                return Err(ProtocolError::UnknownNbtTag(0));
            }
            let len = raw_len as usize;
            if element_type == TagType::Compound {
                if depth >= MAX_NBT_DEPTH {
                    return Err(ProtocolError::UnknownNbtTag(0));
                }
                let mut items = Vec::with_capacity(len.min(65536));
                for _ in 0..len {
                    items.push(read_tag_payload_depth(element_type, src, depth + 1)?);
                }
                Ok(NbtTag::List(items))
            } else {
                let mut items = Vec::with_capacity(len.min(65536));
                for _ in 0..len {
                    items.push(read_tag_payload_depth(element_type, src, depth)?);
                }
                Ok(NbtTag::List(items))
            }
        },
        TagType::Compound => {
            if depth >= MAX_NBT_DEPTH {
                return Err(ProtocolError::UnknownNbtTag(0));
            }
            let mut map = HashMap::new();
            loop {
                if src.is_empty() {
                    return Err(ProtocolError::UnexpectedEof);
                }
                let type_byte = src.get_u8();
                let tag_type = TagType::from_u8(type_byte)?;
                if tag_type == TagType::End {
                    break;
                }
                let name = read_nbt_string(src)?;
                let tag = read_tag_payload_depth(tag_type, src, depth + 1)?;
                map.insert(name, tag);
            }
            Ok(NbtTag::Compound(map))
        },
        TagType::IntArray => {
            if src.remaining() < 4 {
                return Err(ProtocolError::UnexpectedEof);
            }
            let raw_len = src.get_i32();
            if !(0..=MAX_NBT_ARRAY_LEN).contains(&raw_len) {
                return Err(ProtocolError::UnknownNbtTag(0));
            }
            let len = raw_len as usize;
            let mut arr = Vec::with_capacity(len.min(65536));
            for _ in 0..len {
                if src.remaining() < 4 {
                    return Err(ProtocolError::UnexpectedEof);
                }
                arr.push(src.get_i32());
            }
            Ok(NbtTag::IntArray(arr))
        },
        TagType::LongArray => {
            if src.remaining() < 4 {
                return Err(ProtocolError::UnexpectedEof);
            }
            let raw_len = src.get_i32();
            if !(0..=MAX_NBT_ARRAY_LEN).contains(&raw_len) {
                return Err(ProtocolError::UnknownNbtTag(0));
            }
            let len = raw_len as usize;
            let mut arr = Vec::with_capacity(len.min(65536));
            for _ in 0..len {
                if src.remaining() < 8 {
                    return Err(ProtocolError::UnexpectedEof);
                }
                arr.push(src.get_i64());
            }
            Ok(NbtTag::LongArray(arr))
        },
    }
}

fn write_tag_payload(tag: &NbtTag, dst: &mut BytesMut) -> Result<(), ProtocolError> {
    match tag {
        NbtTag::End => Ok(()),
        NbtTag::Byte(v) => {
            dst.put_i8(*v);
            Ok(())
        },
        NbtTag::Short(v) => {
            dst.put_i16(*v);
            Ok(())
        },
        NbtTag::Int(v) => {
            dst.put_i32(*v);
            Ok(())
        },
        NbtTag::Long(v) => {
            dst.put_i64(*v);
            Ok(())
        },
        NbtTag::Float(v) => {
            dst.put_f32(*v);
            Ok(())
        },
        NbtTag::Double(v) => {
            dst.put_f64(*v);
            Ok(())
        },
        NbtTag::ByteArray(arr) => {
            dst.put_i32(arr.len() as i32);
            for b in arr {
                dst.put_i8(*b);
            }
            Ok(())
        },
        NbtTag::String(s) => write_nbt_string(s, dst),
        NbtTag::List(items) => {
            let elem_type = items.first().map(tag_type_byte).unwrap_or(0);
            dst.put_u8(elem_type);
            dst.put_i32(items.len() as i32);
            for item in items {
                write_tag_payload(item, dst)?;
            }
            Ok(())
        },
        NbtTag::Compound(map) => {
            for (name, tag) in map {
                dst.put_u8(tag_type_byte(tag));
                write_nbt_string(name, dst)?;
                write_tag_payload(tag, dst)?;
            }
            dst.put_u8(TagType::End as u8);
            Ok(())
        },
        NbtTag::IntArray(arr) => {
            dst.put_i32(arr.len() as i32);
            for v in arr {
                dst.put_i32(*v);
            }
            Ok(())
        },
        NbtTag::LongArray(arr) => {
            dst.put_i32(arr.len() as i32);
            for v in arr {
                dst.put_i64(*v);
            }
            Ok(())
        },
    }
}

fn tag_type_byte(tag: &NbtTag) -> u8 {
    match tag {
        NbtTag::End => 0,
        NbtTag::Byte(_) => 1,
        NbtTag::Short(_) => 2,
        NbtTag::Int(_) => 3,
        NbtTag::Long(_) => 4,
        NbtTag::Float(_) => 5,
        NbtTag::Double(_) => 6,
        NbtTag::ByteArray(_) => 7,
        NbtTag::String(_) => 8,
        NbtTag::List(_) => 9,
        NbtTag::Compound(_) => 10,
        NbtTag::IntArray(_) => 11,
        NbtTag::LongArray(_) => 12,
    }
}

impl Encode for Nbt {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_u8(TagType::Compound as u8);
        write_nbt_string(&self.name, dst)?;
        let compound = NbtTag::Compound(self.root.clone());
        write_tag_payload(&compound, dst)?;
        Ok(())
    }
}

impl Decode for Nbt {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        if src.is_empty() {
            return Err(ProtocolError::UnexpectedEof);
        }
        let type_byte = src.get_u8();
        if type_byte == 0 {
            return Ok(Nbt::empty(""));
        }
        let tag_type = TagType::from_u8(type_byte)?;
        let name = read_nbt_string(src)?;
        let payload = read_tag_payload(tag_type, src)?;
        match payload {
            NbtTag::Compound(map) => Ok(Nbt { name, root: map }),
            _ => Err(ProtocolError::UnknownNbtTag(type_byte)),
        }
    }
}

impl Nbt {
    pub fn get(&self, key: &str) -> Option<&NbtTag> {
        self.root.get(key)
    }

    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.root.get(key)? {
            NbtTag::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn get_int(&self, key: &str) -> Option<i32> {
        match self.root.get(key)? {
            NbtTag::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_long(&self, key: &str) -> Option<i64> {
        match self.root.get(key)? {
            NbtTag::Long(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_compound(&self, key: &str) -> Option<&HashMap<String, NbtTag>> {
        match self.root.get(key)? {
            NbtTag::Compound(map) => Some(map),
            _ => None,
        }
    }

    pub fn get_list(&self, key: &str) -> Option<&Vec<NbtTag>> {
        match self.root.get(key)? {
            NbtTag::List(list) => Some(list),
            _ => None,
        }
    }

    pub fn insert(&mut self, key: String, tag: NbtTag) {
        self.root.insert(key, tag);
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.root.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.root.len()
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_empty()
    }
}

impl NbtTag {
    pub fn string(s: impl Into<String>) -> Self {
        NbtTag::String(s.into())
    }

    pub fn int(v: i32) -> Self {
        NbtTag::Int(v)
    }

    pub fn long(v: i64) -> Self {
        NbtTag::Long(v)
    }

    pub fn byte(v: i8) -> Self {
        NbtTag::Byte(v)
    }

    pub fn short(v: i16) -> Self {
        NbtTag::Short(v)
    }

    pub fn float(v: f32) -> Self {
        NbtTag::Float(v)
    }

    pub fn double(v: f64) -> Self {
        NbtTag::Double(v)
    }

    pub fn compound() -> Self {
        NbtTag::Compound(HashMap::new())
    }

    pub fn list() -> Self {
        NbtTag::List(Vec::new())
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            NbtTag::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i32> {
        match self {
            NbtTag::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_long(&self) -> Option<i64> {
        match self {
            NbtTag::Long(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_compound(&self) -> Option<&HashMap<String, NbtTag>> {
        match self {
            NbtTag::Compound(map) => Some(map),
            _ => None,
        }
    }

    pub fn as_compound_mut(&mut self) -> Option<&mut HashMap<String, NbtTag>> {
        match self {
            NbtTag::Compound(map) => Some(map),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&Vec<NbtTag>> {
        match self {
            NbtTag::List(list) => Some(list),
            _ => None,
        }
    }

    pub fn as_list_mut(&mut self) -> Option<&mut Vec<NbtTag>> {
        match self {
            NbtTag::List(list) => Some(list),
            _ => None,
        }
    }
}

// The on-wire NBT used by JoinGame's dimension codec and a handful of other
// 1.13+ packets is self-delimiting — but only if you decode it. When we
// want to *step over* a codec without materialising the tree (e.g. when
// translating between protocol versions that no longer carry it), we need
// a streaming skipper that honours every tag's payload shape.
//
// `skip` consumes a single top-level NBT value from `cur` and advances
// past it. Returns the count of bytes consumed.

/// Advance `cur` past one top-level NBT value. Returns the number of
/// bytes consumed. Surfaces `ProtocolError::UnexpectedEof` /
/// `UnknownNbtTag` on malformed input so callers can react (most
/// converters turn that into `ConversionResult::Drop`).
pub fn skip(cur: &mut Bytes) -> Result<usize, ProtocolError> {
    let start = cur.remaining();
    if start < 1 {
        return Err(ProtocolError::UnexpectedEof);
    }
    let tag_byte = cur.get_u8();
    if tag_byte == TagType::End as u8 {
        return Ok(start - cur.remaining());
    }
    let tag = TagType::from_u8(tag_byte)?;
    // Top-level value carries a name prefix: u16 length + UTF-8 bytes.
    skip_name(cur)?;
    skip_payload_depth(cur, tag, 0)?;
    Ok(start - cur.remaining())
}

fn skip_name(cur: &mut Bytes) -> Result<(), ProtocolError> {
    if cur.remaining() < 2 {
        return Err(ProtocolError::UnexpectedEof);
    }
    let len = cur.get_u16() as usize;
    if cur.remaining() < len {
        return Err(ProtocolError::UnexpectedEof);
    }
    cur.advance(len);
    Ok(())
}

fn skip_payload_depth(cur: &mut Bytes, tag: TagType, depth: usize) -> Result<(), ProtocolError> {
    match tag {
        TagType::End => Ok(()),
        TagType::Byte => need(cur, 1),
        TagType::Short => need(cur, 2),
        TagType::Int | TagType::Float => need(cur, 4),
        TagType::Long | TagType::Double => need(cur, 8),
        TagType::ByteArray => {
            need(cur, 4)?;
            let n = cur.get_i32();
            if n < 0 {
                return Err(ProtocolError::UnknownNbtTag(0));
            }
            need(cur, n as usize)
        },
        TagType::String => {
            need(cur, 2)?;
            let n = cur.get_u16() as usize;
            need(cur, n)
        },
        TagType::List => {
            need(cur, 5)?;
            let inner = TagType::from_u8(cur.get_u8())?;
            let n = cur.get_i32();
            if n < 0 {
                return Err(ProtocolError::UnknownNbtTag(0));
            }
            if inner == TagType::Compound || inner == TagType::List {
                if depth >= MAX_NBT_DEPTH {
                    return Err(ProtocolError::UnknownNbtTag(0));
                }
                for _ in 0..n {
                    skip_payload_depth(cur, inner, depth + 1)?;
                }
            } else {
                for _ in 0..n {
                    skip_payload_depth(cur, inner, depth)?;
                }
            }
            Ok(())
        },
        TagType::Compound => {
            if depth >= MAX_NBT_DEPTH {
                return Err(ProtocolError::UnknownNbtTag(0));
            }
            loop {
                if cur.remaining() < 1 {
                    return Err(ProtocolError::UnexpectedEof);
                }
                let child_byte = cur.get_u8();
                if child_byte == TagType::End as u8 {
                    return Ok(());
                }
                let child = TagType::from_u8(child_byte)?;
                skip_name(cur)?;
                skip_payload_depth(cur, child, depth + 1)?;
            }
        },
        TagType::IntArray => {
            need(cur, 4)?;
            let n = cur.get_i32();
            if n < 0 {
                return Err(ProtocolError::UnknownNbtTag(0));
            }
            need(cur, (n as usize).saturating_mul(4))
        },
        TagType::LongArray => {
            need(cur, 4)?;
            let n = cur.get_i32();
            if n < 0 {
                return Err(ProtocolError::UnknownNbtTag(0));
            }
            need(cur, (n as usize).saturating_mul(8))
        },
    }
}

fn need(cur: &mut Bytes, n: usize) -> Result<(), ProtocolError> {
    if cur.remaining() < n {
        return Err(ProtocolError::UnexpectedEof);
    }
    cur.advance(n);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nbt_helpers() {
        let mut nbt = Nbt::empty("test");
        nbt.insert("name".to_string(), NbtTag::string("Steve"));
        nbt.insert("level".to_string(), NbtTag::int(42));

        assert_eq!(nbt.get_string("name"), Some("Steve"));
        assert_eq!(nbt.get_int("level"), Some(42));
        assert_eq!(nbt.len(), 2);
        assert!(nbt.contains_key("name"));
    }

    #[test]
    fn tag_conversions() {
        let tag = NbtTag::string("hello");
        assert_eq!(tag.as_string(), Some("hello"));
        assert_eq!(tag.as_int(), None);

        let tag = NbtTag::int(100);
        assert_eq!(tag.as_int(), Some(100));
        assert_eq!(tag.as_string(), None);
    }

    #[test]
    fn skip_walks_past_empty_compound() {
        // tag=Compound(10), name_len=0, then immediate End(0)
        let raw: &[u8] = &[10, 0, 0, 0];
        let mut buf = Bytes::copy_from_slice(raw);
        skip(&mut buf).expect("skip");
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn skip_returns_err_on_truncated_input() {
        let raw: &[u8] = &[10, 0]; // missing name_len trailing byte
        let mut buf = Bytes::copy_from_slice(raw);
        assert!(skip(&mut buf).is_err());
    }

    #[test]
    fn skip_handles_explicit_end_at_top_level() {
        let raw: &[u8] = &[0]; // bare TAG_End
        let mut buf = Bytes::copy_from_slice(raw);
        skip(&mut buf).expect("skip end");
        assert_eq!(buf.remaining(), 0);
    }
}
