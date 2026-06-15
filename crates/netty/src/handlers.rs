//! Channel handler trait + context type.
//!
//! [`ChannelHandler`] is what pipeline stages implement; each handler
//! receives a [`ChannelContext`] giving it the ability to forward
//! data to the next handler, fire events, or close the channel.
//! [`Direction::Inbound`] / `Outbound` lets the same handler sit on
//! either side of the pipeline.

use bytes::{BufMut, Bytes, BytesMut};
use kojacoord_protocol::codec::{Decode as _, Encode as _};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

pub struct ChannelContext {
    pub compression_threshold: i32,
    pub protocol_version: u32,
}

pub trait ChannelHandler: Send + Sync {
    fn name(&self) -> &'static str;

    fn handle_inbound(
        &self,
        ctx: &mut ChannelContext,
        data: Bytes,
    ) -> Result<Option<Bytes>, super::error::HandlerError>;

    fn handle_outbound(
        &self,
        ctx: &mut ChannelContext,
        data: Bytes,
    ) -> Result<Option<Bytes>, super::error::HandlerError>;
}

pub struct CompressionHandler;

impl ChannelHandler for CompressionHandler {
    fn name(&self) -> &'static str {
        "compression"
    }

    fn handle_inbound(
        &self,
        _ctx: &mut ChannelContext,
        data: Bytes,
    ) -> Result<Option<Bytes>, super::error::HandlerError> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        let mut cursor = data.clone();

        let data_len = kojacoord_protocol::types::VarInt::decode(&mut cursor)
            .map_err(super::error::HandlerError::Protocol)?
            .0;

        if data_len == 0 {
            return Ok(Some(cursor));
        }

        const MAX_UNCOMPRESSED: usize = 32 * 1024 * 1024;

        if data_len < 0 || (data_len as usize) > MAX_UNCOMPRESSED {
            return Err(super::error::HandlerError::InvalidDataLength(data_len));
        }

        let mut decoder = ZlibDecoder::new(cursor.as_ref());
        let mut decompressed = Vec::with_capacity(data_len as usize);
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| super::error::HandlerError::Compression(e.to_string()))?;

        Ok(Some(Bytes::from(decompressed)))
    }

    fn handle_outbound(
        &self,
        ctx: &mut ChannelContext,
        data: Bytes,
    ) -> Result<Option<Bytes>, super::error::HandlerError> {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;

        let threshold = ctx.compression_threshold;

        if threshold < 0 {
            return Ok(Some(data));
        }

        let mut out = BytesMut::new();

        if (data.len() as i32) < threshold {
            kojacoord_protocol::types::VarInt(0)
                .encode(&mut out)
                .map_err(super::error::HandlerError::Protocol)?;
            out.extend_from_slice(&data);
        } else {
            kojacoord_protocol::types::VarInt(data.len() as i32)
                .encode(&mut out)
                .map_err(super::error::HandlerError::Protocol)?;

            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&data)
                .map_err(|e| super::error::HandlerError::Compression(e.to_string()))?;
            let compressed = enc
                .finish()
                .map_err(|e| super::error::HandlerError::Compression(e.to_string()))?;

            out.put_slice(&compressed);
        }

        Ok(Some(out.freeze()))
    }
}
