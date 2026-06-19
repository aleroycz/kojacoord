//! Minimal Minecraft packet wire for the realm client login.
//!
//! Self-contained on purpose (the realm connection is online-mode and
//! AES-encrypted end to end, unlike the proxy's offline backend path):
//!   * [`EncryptedStream`] — wraps a byte stream with an optional AES-CFB8
//!     cipher pair that is switched on mid-login after EncryptionResponse.
//!   * [`read_packet`] / [`write_packet`] — length-prefixed framing with the
//!     post-`SetCompression` zlib format.
//!
//! Only the modern (1.20.5+) login wire is needed since Realms runs the latest
//! release.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use kojacoord_auth::encryption::{Aes128CfbDec, Aes128CfbEnc};
use kojacoord_protocol::codec::{Decode, Encode};
use kojacoord_protocol::types::VarInt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::net::packet_io::read_varint;

/// A stream that transparently AES-CFB8 encrypts writes and decrypts reads once
/// [`EncryptedStream::enable`] is called. Before that it is a pass-through.
pub struct EncryptedStream<S> {
    inner: S,
    enc: Option<Aes128CfbEnc>,
    dec: Option<Aes128CfbDec>,
    /// Encrypted bytes awaiting write-out to `inner`.
    pending: BytesMut,
}

impl<S> EncryptedStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            enc: None,
            dec: None,
            pending: BytesMut::new(),
        }
    }

    /// Switch on encryption with the negotiated shared secret as both key & IV
    /// (Minecraft AES-128-CFB8).
    pub fn enable(&mut self, enc: Aes128CfbEnc, dec: Aes128CfbDec) {
        self.enc = Some(enc);
        self.dec = Some(dec);
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let pre = buf.filled().len();
        match Pin::new(&mut me.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if let Some(dec) = me.dec.as_mut() {
                    // CFB8 decrypts in place, advancing the feedback state.
                    dec.decrypt(&mut buf.filled_mut()[pre..]);
                }
                Poll::Ready(Ok(()))
            },
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if let Some(enc) = me.enc.as_mut() {
            let mut chunk = buf.to_vec();
            enc.encrypt(&mut chunk);
            me.pending.extend_from_slice(&chunk);
        } else {
            me.pending.extend_from_slice(buf);
        }
        // Opportunistically drain; if it would block, the bytes stay buffered
        // and go out on the next poll_write / poll_flush.
        let _ = drain(&mut me.inner, &mut me.pending, cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match drain(&mut me.inner, &mut me.pending, cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match drain(&mut me.inner, &mut me.pending, cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Write out as much of `pending` as the inner stream will accept right now.
fn drain<S: AsyncWrite + Unpin>(
    inner: &mut S,
    pending: &mut BytesMut,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while !pending.is_empty() {
        match Pin::new(&mut *inner).poll_write(cx, pending) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "realm stream closed",
                )))
            },
            Poll::Ready(Ok(n)) => {
                pending.advance(n);
            },
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

// ── VarInt / string framing (reusing the protocol crate's codec) ─────────────

fn io_err(e: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

pub fn put_varint(buf: &mut BytesMut, v: i32) {
    VarInt(v).encode(buf).expect("VarInt encode is infallible");
}

pub fn put_string(buf: &mut BytesMut, s: &str) {
    put_varint(buf, s.len() as i32);
    buf.put_slice(s.as_bytes());
}

/// Read a VarInt from an in-memory cursor via the shared codec.
pub fn take_varint(buf: &mut Bytes) -> io::Result<i32> {
    VarInt::decode(buf).map(|v| v.0).map_err(io_err)
}

pub fn take_string(buf: &mut Bytes) -> io::Result<String> {
    let len = take_varint(buf)? as usize;
    if buf.remaining() < len {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "string eof"));
    }
    String::from_utf8(buf.split_to(len).to_vec()).map_err(io_err)
}

pub fn take_bytes(buf: &mut Bytes) -> io::Result<Bytes> {
    let len = take_varint(buf)? as usize;
    if buf.remaining() < len {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "bytes eof"));
    }
    Ok(buf.split_to(len))
}

/// A decoded clientbound packet: its id and the remaining body bytes.
pub struct Packet {
    pub id: i32,
    pub body: Bytes,
}

/// Write one packet `[len][id][data]`, applying the post-SetCompression zlib
/// format when `compression` is `Some(threshold)`.
pub async fn write_packet<W: AsyncWrite + Unpin>(
    dst: &mut W,
    compression: Option<i32>,
    id: i32,
    data: &[u8],
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    put_varint(&mut payload, id);
    payload.put_slice(data);

    let mut frame = BytesMut::new();
    match compression {
        None => {
            put_varint(&mut frame, payload.len() as i32);
            frame.extend_from_slice(&payload);
        },
        Some(threshold) => {
            let mut inner = BytesMut::new();
            if (payload.len() as i32) >= threshold.max(0) && threshold >= 0 {
                let compressed = zlib_compress(&payload)?;
                put_varint(&mut inner, payload.len() as i32);
                inner.extend_from_slice(&compressed);
            } else {
                put_varint(&mut inner, 0);
                inner.extend_from_slice(&payload);
            }
            put_varint(&mut frame, inner.len() as i32);
            frame.extend_from_slice(&inner);
        },
    }
    dst.write_all(&frame).await?;
    dst.flush().await
}

/// Read one packet, undoing the compression format when enabled.
pub async fn read_packet<R: AsyncRead + Unpin>(
    src: &mut R,
    compression: Option<i32>,
) -> io::Result<Packet> {
    let len = read_varint(src).await.map_err(io_err)? as usize;
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero-length frame",
        ));
    }
    let mut frame = vec![0u8; len];
    src.read_exact(&mut frame).await?;

    let mut payload = match compression {
        None => Bytes::from(frame),
        Some(_) => {
            let mut cur = Bytes::from(frame);
            let data_len = take_varint(&mut cur)? as usize;
            if data_len == 0 {
                cur
            } else {
                Bytes::from(zlib_decompress(&cur, data_len)?)
            }
        },
    };

    let id = take_varint(&mut payload)?;
    Ok(Packet { id, body: payload })
}

fn zlib_compress(data: &[u8]) -> io::Result<Vec<u8>> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data)?;
    e.finish()
}

fn zlib_decompress(data: &[u8], expected: usize) -> io::Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut out = Vec::with_capacity(expected);
    ZlibDecoder::new(data).read_to_end(&mut out)?;
    Ok(out)
}
