//! HAProxy PROXY protocol v1/v2 parser.
//!
//! When the proxy sits behind a TCP load balancer (HAProxy, AWS NLB,
//! Cloudflare Spectrum), the L4 in front strips the real client IP
//! and replaces it with its own. The PROXY protocol is a small header
//! prepended to the TCP stream that carries the original client
//! address so downstream services can log/rate-limit by the real
//! source.
//!
//! Two modes: [`read_proxy_header`] is strict — header must be there
//! or the connection is rejected — and [`read_proxy_header_optional`]
//! sniffs the first six bytes, falls back to a vanilla Minecraft
//! handshake if no PROXY signature is found, and returns the consumed
//! bytes for the caller to re-feed into the handshake parser.
use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncReadExt;

use crate::error::ConnectionError;

const V2_SIG: &[u8] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
const V1_SIG: &[u8] = b"PROXY ";

pub enum ProxyHeaderResult {
    Found(SocketAddr),
    NotFound(Vec<u8>),
}

fn is_trusted(src_ip: IpAddr, trusted_proxies: &[ipnet::IpNet]) -> bool {
    trusted_proxies.iter().any(|net| net.contains(&src_ip))
}

pub async fn read_proxy_header_optional<R: AsyncReadExt + Unpin>(
    src: &mut R,
    peer_addr: SocketAddr,
    trusted_proxies: &[ipnet::IpNet],
) -> Result<ProxyHeaderResult, ConnectionError> {
    let mut header_buf = [0u8; 512];
    let mut pos = 0;

    match src.read_exact(&mut header_buf[0..6]).await {
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(ProxyHeaderResult::NotFound(vec![]));
        },
        Err(e) => return Err(ConnectionError::Io(e)),
    }
    pos += 6;

    if &header_buf[0..6] == V1_SIG {
        loop {
            if pos >= header_buf.len() {
                return Err(ConnectionError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "PROXY v1 header too long",
                )));
            }
            let byte = src.read_u8().await?;
            header_buf[pos] = byte;
            pos += 1;
            if byte == b'\n' {
                break;
            }
        }

        let header_str = std::str::from_utf8(&header_buf[..pos]).unwrap_or("");
        let parts: Vec<&str> = header_str.split(' ').collect();
        if parts.len() >= 6 {
            if let Ok(ip) = parts[2].parse::<IpAddr>() {
                if let Ok(port) = parts[4].parse::<u16>() {
                    if !trusted_proxies.is_empty() && !is_trusted(peer_addr.ip(), trusted_proxies) {
                        tracing::warn!(
                            peer = %peer_addr,
                            "PROXY v1 header from untrusted source, ignoring"
                        );
                        return Ok(ProxyHeaderResult::NotFound(header_buf[..pos].to_vec()));
                    }
                    tracing::debug!(real_addr = %SocketAddr::new(ip, port), "PROXY v1 header parsed");
                    return Ok(ProxyHeaderResult::Found(SocketAddr::new(ip, port)));
                }
            }
        }
        return Err(ConnectionError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Malformed PROXY v1 header",
        )));
    } else if header_buf[0..6] == V2_SIG[0..6] {
        src.read_exact(&mut header_buf[6..16]).await?;
        pos += 10;

        if header_buf[0..12] != *V2_SIG {
            return Ok(ProxyHeaderResult::NotFound(header_buf[..pos].to_vec()));
        }

        let fam = header_buf[13];
        let addr_len = u16::from_be_bytes([header_buf[14], header_buf[15]]) as usize;
        if pos + addr_len > header_buf.len() {
            return Err(ConnectionError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PROXY v2 header too long",
            )));
        }

        src.read_exact(&mut header_buf[16..16 + addr_len]).await?;
        pos += addr_len;

        if fam == 0x11 && addr_len >= 12 {
            let ip = std::net::Ipv4Addr::new(
                header_buf[16],
                header_buf[17],
                header_buf[18],
                header_buf[19],
            );
            let port = u16::from_be_bytes([header_buf[24], header_buf[25]]);
            if !trusted_proxies.is_empty() && !is_trusted(peer_addr.ip(), trusted_proxies) {
                tracing::warn!(
                    peer = %peer_addr,
                    "PROXY v2 header from untrusted source, ignoring"
                );
                return Ok(ProxyHeaderResult::NotFound(header_buf[..pos].to_vec()));
            }
            tracing::debug!(real_addr = %SocketAddr::new(IpAddr::V4(ip), port), "PROXY v2 header parsed");
            return Ok(ProxyHeaderResult::Found(SocketAddr::new(
                IpAddr::V4(ip),
                port,
            )));
        } else if fam == 0x21 && addr_len >= 36 {
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&header_buf[16..32]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([header_buf[48], header_buf[49]]);
            if !trusted_proxies.is_empty() && !is_trusted(peer_addr.ip(), trusted_proxies) {
                tracing::warn!(
                    peer = %peer_addr,
                    "PROXY v2 header from untrusted source, ignoring"
                );
                return Ok(ProxyHeaderResult::NotFound(header_buf[..pos].to_vec()));
            }
            tracing::debug!(real_addr = %SocketAddr::new(IpAddr::V6(ip), port), "PROXY v2 header parsed");
            return Ok(ProxyHeaderResult::Found(SocketAddr::new(
                IpAddr::V6(ip),
                port,
            )));
        }

        return Ok(ProxyHeaderResult::NotFound(header_buf[..pos].to_vec()));
    }

    tracing::debug!("No PROXY header detected, assuming direct connection");
    Ok(ProxyHeaderResult::NotFound(header_buf[..6].to_vec()))
}

pub async fn peek_proxy_header<R: AsyncReadExt + Unpin>(src: &mut R) -> Option<SocketAddr> {
    let mut peek_buf = [0u8; 16];

    match src.read_exact(&mut peek_buf[0..6]).await {
        Ok(_) => {},
        Err(_) => return None,
    }

    if &peek_buf[0..6] == V1_SIG {
        return None;
    } else if peek_buf[0..6] == V2_SIG[0..6] {
        if src.read_exact(&mut peek_buf[6..16]).await.is_err() {
            return None;
        }

        if peek_buf[0..12] != *V2_SIG {
            return None;
        }

        let fam = peek_buf[13];
        let addr_len = u16::from_be_bytes([peek_buf[14], peek_buf[15]]) as usize;

        if addr_len > 36 {
            return None;
        }

        let mut addr_buf = vec![0u8; addr_len];
        if src.read_exact(&mut addr_buf).await.is_err() {
            return None;
        }

        if fam == 0x11 && addr_len >= 12 {
            let ip = std::net::Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
            let port = u16::from_be_bytes([addr_buf[8], addr_buf[9]]);
            return Some(SocketAddr::new(IpAddr::V4(ip), port));
        } else if fam == 0x21 && addr_len >= 36 {
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&addr_buf[0..16]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([addr_buf[32], addr_buf[33]]);
            return Some(SocketAddr::new(IpAddr::V6(ip), port));
        }
    }

    None
}

pub async fn read_proxy_header<R: AsyncReadExt + Unpin>(
    src: &mut R,
    current_addr: SocketAddr,
    trusted_proxies: &[ipnet::IpNet],
) -> Result<SocketAddr, ConnectionError> {
    let mut header_buf = [0u8; 512];
    let mut pos = 0;

    src.read_exact(&mut header_buf[0..6]).await?;
    pos += 6;

    if &header_buf[0..6] == V1_SIG {
        loop {
            if pos >= header_buf.len() {
                return Err(ConnectionError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "PROXY v1 header too long",
                )));
            }
            let byte = src.read_u8().await?;
            header_buf[pos] = byte;
            pos += 1;
            if byte == b'\n' {
                break;
            }
        }

        let header_str = std::str::from_utf8(&header_buf[..pos]).unwrap_or("");
        let parts: Vec<&str> = header_str.split(' ').collect();
        if parts.len() >= 6 {
            if let Ok(ip) = parts[2].parse::<IpAddr>() {
                if let Ok(port) = parts[4].parse::<u16>() {
                    if !trusted_proxies.is_empty()
                        && !is_trusted(current_addr.ip(), trusted_proxies)
                    {
                        tracing::warn!(
                            peer = %current_addr,
                            "PROXY v1 header from untrusted source, using peer address"
                        );
                        return Ok(current_addr);
                    }
                    return Ok(SocketAddr::new(ip, port));
                }
            }
        }
        return Err(ConnectionError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Malformed PROXY v1 header",
        )));
    } else if header_buf[0..6] == V2_SIG[0..6] {
        src.read_exact(&mut header_buf[6..16]).await?;
        pos += 10;

        if header_buf[0..12] != *V2_SIG {
            return Err(ConnectionError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid PROXY v2 signature",
            )));
        }

        let fam = header_buf[13];
        let addr_len = u16::from_be_bytes([header_buf[14], header_buf[15]]) as usize;
        if pos + addr_len > header_buf.len() {
            return Err(ConnectionError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PROXY v2 header too long",
            )));
        }

        src.read_exact(&mut header_buf[16..16 + addr_len]).await?;

        if fam == 0x11 && addr_len >= 12 {
            let ip = std::net::Ipv4Addr::new(
                header_buf[16],
                header_buf[17],
                header_buf[18],
                header_buf[19],
            );
            let port = u16::from_be_bytes([header_buf[24], header_buf[25]]);
            if !trusted_proxies.is_empty() && !is_trusted(current_addr.ip(), trusted_proxies) {
                tracing::warn!(
                    peer = %current_addr,
                    "PROXY v2 header from untrusted source, using peer address"
                );
                return Ok(current_addr);
            }
            return Ok(SocketAddr::new(IpAddr::V4(ip), port));
        } else if fam == 0x21 && addr_len >= 36 {
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&header_buf[16..32]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([header_buf[48], header_buf[49]]);
            if !trusted_proxies.is_empty() && !is_trusted(current_addr.ip(), trusted_proxies) {
                tracing::warn!(
                    peer = %current_addr,
                    "PROXY v2 header from untrusted source, using peer address"
                );
                return Ok(current_addr);
            }
            return Ok(SocketAddr::new(IpAddr::V6(ip), port));
        }

        return Err(ConnectionError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Malformed PROXY v2 header: unknown address family",
        )));
    }

    Err(ConnectionError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Expected PROXY header, but signature did not match",
    )))
}
