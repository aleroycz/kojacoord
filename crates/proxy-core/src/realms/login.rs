//! Online-mode client login to a realm's game server.
//!
//! Unlike the proxy's offline backend path, a Realm is a genuine online-mode
//! server: it issues an EncryptionRequest and verifies the joining account
//! against Mojang's session server. This module performs the full client side
//! of that exchange using the service account's `access_token`, then hands back
//! an [`EncryptedStream`] (and the negotiated compression threshold) positioned
//! at the start of the configuration phase, ready to relay.
//!
//! Only the modern (1.20.5+) login wire is implemented — Realms runs the latest
//! release exclusively.

use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use tokio::net::TcpStream;
use uuid::Uuid;

use kojacoord_auth::encryption::init_aes_cfb8;
use kojacoord_auth::session::minecraft_hex_digest;

use super::credentials::ServiceAccount;
use super::wire::{take_bytes, take_string, take_varint, write_packet, EncryptedStream, Packet};
use super::RealmsError;

const SESSION_JOIN_URL: &str = "https://sessionserver.mojang.com/session/minecraft/join";

// Clientbound login packet ids (modern).
const CB_DISCONNECT: i32 = 0x00;
const CB_ENCRYPTION_REQUEST: i32 = 0x01;
const CB_LOGIN_SUCCESS: i32 = 0x02;
const CB_SET_COMPRESSION: i32 = 0x03;
const CB_LOGIN_PLUGIN_REQUEST: i32 = 0x04;

// Serverbound login packet ids (modern).
const SB_LOGIN_START: i32 = 0x00;
const SB_ENCRYPTION_RESPONSE: i32 = 0x01;
const SB_LOGIN_PLUGIN_RESPONSE: i32 = 0x02;
const SB_LOGIN_ACKNOWLEDGED: i32 = 0x03;

/// A live, authenticated connection to a realm, sitting just after
/// LoginSuccess (the client has acknowledged login; the next bytes are the
/// configuration phase).
pub struct RealmConnection {
    pub stream: EncryptedStream<TcpStream>,
    /// Negotiated compression threshold, or `None` if compression was never
    /// enabled. The relay must frame subsequent packets accordingly.
    pub compression: Option<i32>,
}

/// Perform the full online-mode login to `host:port` as `account`.
///
/// * `protocol` — the protocol version number to advertise in the handshake.
/// * `handshake_host` — the address string to put in the handshake (the join
///   address host; some servers route on it).
pub async fn connect(
    host: &str,
    port: u16,
    protocol: i32,
    account: &ServiceAccount,
    http: &reqwest::Client,
) -> Result<RealmConnection, RealmsError> {
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| RealmsError::Login(format!("connect {host}:{port}: {e}")))?;
    let mut stream = EncryptedStream::new(tcp);
    let mut compression: Option<i32> = None;

    send_handshake(&mut stream, protocol, host, port).await?;
    send_login_start(&mut stream, account).await?;

    loop {
        let pkt = super::wire::read_packet(&mut stream, compression)
            .await
            .map_err(|e| RealmsError::Login(format!("read login packet: {e}")))?;
        match pkt.id {
            CB_SET_COMPRESSION => {
                let mut cur = pkt.body.clone();
                let threshold = take_varint(&mut cur)
                    .map_err(|e| RealmsError::Login(format!("set compression: {e}")))?;
                compression = if threshold >= 0 {
                    Some(threshold)
                } else {
                    None
                };
            },
            CB_ENCRYPTION_REQUEST => {
                handle_encryption_request(&mut stream, compression, &pkt, account, http).await?;
            },
            CB_LOGIN_SUCCESS => {
                // Acknowledge to advance into the configuration phase.
                write_packet(&mut stream, compression, SB_LOGIN_ACKNOWLEDGED, &[])
                    .await
                    .map_err(|e| RealmsError::Login(format!("login ack: {e}")))?;
                return Ok(RealmConnection {
                    stream,
                    compression,
                });
            },
            CB_LOGIN_PLUGIN_REQUEST => {
                respond_plugin_request(&mut stream, compression, &pkt).await?;
            },
            CB_DISCONNECT => {
                let mut cur = pkt.body.clone();
                let reason = take_string(&mut cur).unwrap_or_else(|_| "<unknown>".into());
                return Err(RealmsError::Login(format!("realm disconnected: {reason}")));
            },
            other => {
                return Err(RealmsError::Login(format!(
                    "unexpected login packet id {other:#x}"
                )));
            },
        }
    }
}

async fn send_handshake(
    stream: &mut EncryptedStream<TcpStream>,
    protocol: i32,
    host: &str,
    port: u16,
) -> Result<(), RealmsError> {
    use super::wire::{put_string, put_varint};
    use bytes::{BufMut, BytesMut};
    let mut body = BytesMut::new();
    put_varint(&mut body, protocol);
    put_string(&mut body, host);
    body.put_u16(port);
    put_varint(&mut body, 2); // next state = login
    write_packet(stream, None, 0x00, &body)
        .await
        .map_err(|e| RealmsError::Login(format!("handshake: {e}")))
}

async fn send_login_start(
    stream: &mut EncryptedStream<TcpStream>,
    account: &ServiceAccount,
) -> Result<(), RealmsError> {
    use super::wire::put_string;
    use bytes::{BufMut, BytesMut};
    let mut body = BytesMut::new();
    put_string(&mut body, &account.username);
    let (hi, lo) = account.uuid.as_u64_pair();
    body.put_u64(hi);
    body.put_u64(lo);
    write_packet(stream, None, SB_LOGIN_START, &body)
        .await
        .map_err(|e| RealmsError::Login(format!("login start: {e}")))
}

async fn handle_encryption_request(
    stream: &mut EncryptedStream<TcpStream>,
    compression: Option<i32>,
    pkt: &Packet,
    account: &ServiceAccount,
    http: &reqwest::Client,
) -> Result<(), RealmsError> {
    let mut cur = pkt.body.clone();
    let server_id = take_string(&mut cur).map_err(wrap("encryption server id"))?;
    let public_key_der = take_bytes(&mut cur).map_err(wrap("encryption public key"))?;
    let verify_token = take_bytes(&mut cur).map_err(wrap("encryption verify token"))?;
    // (Trailing `shouldAuthenticate` bool on 1.20.5+ is ignored.)

    // Shared secret: 16 random bytes (AES-128 key).
    let mut shared_secret = [0u8; 16];
    OsRng.fill_bytes(&mut shared_secret);

    // Authorise this login against Mojang's session server.
    let server_hash = minecraft_hex_digest(&server_id, &shared_secret, public_key_der.as_ref());
    session_join(http, account, &server_hash).await?;

    // Encrypt shared secret + verify token with the server's RSA public key.
    let public_key = RsaPublicKey::from_public_key_der(public_key_der.as_ref())
        .map_err(|e| RealmsError::Login(format!("parse realm public key: {e}")))?;
    let enc_secret = public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, &shared_secret)
        .map_err(|e| RealmsError::Login(format!("encrypt shared secret: {e}")))?;
    let enc_token = public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, verify_token.as_ref())
        .map_err(|e| RealmsError::Login(format!("encrypt verify token: {e}")))?;

    use super::wire::put_varint;
    use bytes::{BufMut, BytesMut};
    let mut body = BytesMut::new();
    put_varint(&mut body, enc_secret.len() as i32);
    body.put_slice(&enc_secret);
    put_varint(&mut body, enc_token.len() as i32);
    body.put_slice(&enc_token);
    write_packet(stream, compression, SB_ENCRYPTION_RESPONSE, &body)
        .await
        .map_err(|e| RealmsError::Login(format!("encryption response: {e}")))?;

    // Everything after this point is AES-CFB8 encrypted.
    let (enc, dec) =
        init_aes_cfb8(&shared_secret).map_err(|e| RealmsError::Login(format!("init aes: {e}")))?;
    stream.enable(enc, dec);
    Ok(())
}

async fn respond_plugin_request(
    stream: &mut EncryptedStream<TcpStream>,
    compression: Option<i32>,
    pkt: &Packet,
) -> Result<(), RealmsError> {
    use super::wire::put_varint;
    use bytes::{BufMut, BytesMut};
    let mut cur = pkt.body.clone();
    let message_id = take_varint(&mut cur).map_err(wrap("plugin request id"))?;
    let mut body = BytesMut::new();
    put_varint(&mut body, message_id);
    body.put_u8(0); // understood = false
    write_packet(stream, compression, SB_LOGIN_PLUGIN_RESPONSE, &body)
        .await
        .map_err(|e| RealmsError::Login(format!("plugin response: {e}")))
}

/// POST to `sessionserver/join` so the realm's `hasJoined` check succeeds.
async fn session_join(
    http: &reqwest::Client,
    account: &ServiceAccount,
    server_hash: &str,
) -> Result<(), RealmsError> {
    let body = serde_json::json!({
        "accessToken": account.access_token,
        "selectedProfile": undashed(&account.uuid),
        "serverId": server_hash,
    });
    let resp = http
        .post(SESSION_JOIN_URL)
        .json(&body)
        .send()
        .await
        .map_err(|e| RealmsError::Login(format!("session join request: {e}")))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(RealmsError::Login(format!(
            "session join rejected: {}",
            resp.status()
        )))
    }
}

fn undashed(uuid: &Uuid) -> String {
    uuid.simple().to_string()
}

fn wrap(ctx: &'static str) -> impl Fn(std::io::Error) -> RealmsError {
    move |e| RealmsError::Login(format!("{ctx}: {e}"))
}
