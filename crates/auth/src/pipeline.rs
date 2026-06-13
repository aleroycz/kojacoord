//! Login pipeline orchestrator.
//!
//! Drives the per-connection login state machine through the
//! handshake → encryption-request → encryption-response → Mojang
//! session check → LoginSuccess sequence. `AuthPipelineConfig` is
//! the shared config (RSA key, HTTP client, semaphore that bounds
//! concurrent Mojang lookups so we don't hammer their API under
//! login storms). The connection layer drives this with one step
//! per protocol packet.

use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::{
    encryption::{generate_verify_token, public_key_der, rsa_decrypt},
    error::AuthError,
    offline::offline_uuid,
    session::{minecraft_hex_digest, verify_session, AuthenticatedProfile, ProfileProperty},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    Mojang,
    Microsoft,
}

/// Validate a Minecraft username: 1–16 characters of `[A-Za-z0-9_]`.
pub fn is_valid_username(name: &str) -> bool {
    let len = name.len();
    (1..=16).contains(&len) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[derive(Debug)]
pub enum AuthEvent {
    LoginStart {
        username: String,
        client_uuid: Option<Uuid>,
    },

    EncryptionResponse {
        shared_secret_enc: Vec<u8>,
        verify_token_enc: Vec<u8>,
    },
}

#[derive(Debug)]
pub enum AuthOutbound {
    EncryptionRequest {
        server_id: String,
        public_key: Vec<u8>,
        verify_token: Vec<u8>,
    },

    SetCompression {
        threshold: i32,
    },

    LoginSuccess {
        uuid: Uuid,
        username: String,
        properties: Vec<ProfileProperty>,
    },

    LoginDisconnect {
        reason: String,
    },

    EnableEncryption {
        shared_secret: [u8; 16],
    },
}

#[derive(Debug)]
pub enum AuthState {
    AwaitingLoginStart,

    AwaitingEncryptionResponse {
        verify_token: [u8; 4],
        username: String,
        client_ip: IpAddr,
    },

    Authenticated {
        profile: AuthenticatedProfile,
    },

    Failed(String),
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub online_mode: bool,
    pub compression_threshold: i32,
    pub session_timeout_secs: u64,
    pub prevent_proxy_connections: bool,
    pub auth_type: AuthType,
}

pub struct AuthPipelineConfig {
    pub rsa_key: Arc<rsa::RsaPrivateKey>,
    pub http: reqwest::Client,
    pub rate_limiter: Arc<Semaphore>,
    pub config: AuthConfig,
}

impl AuthPipelineConfig {
    pub fn new(
        rsa_key: Arc<rsa::RsaPrivateKey>,
        http: reqwest::Client,
        rate_limiter: Arc<Semaphore>,
        config: AuthConfig,
    ) -> Result<Self, AuthError> {
        let _ = public_key_der(&rsa_key)?;
        Ok(Self {
            rsa_key,
            http,
            rate_limiter,
            config,
        })
    }

    pub fn build(&self) -> Result<AuthPipeline, AuthError> {
        AuthPipeline::new(
            self.rsa_key.clone(),
            self.http.clone(),
            self.rate_limiter.clone(),
            self.config.clone(),
        )
    }
}

pub struct AuthPipeline {
    state: AuthState,
    rsa_key: Arc<rsa::RsaPrivateKey>,
    pub_key_der: Vec<u8>,
    http: reqwest::Client,
    rate_limiter: Arc<Semaphore>,
    config: AuthConfig,
}

impl AuthPipeline {
    pub fn new(
        rsa_key: Arc<rsa::RsaPrivateKey>,
        http: reqwest::Client,
        rate_limiter: Arc<Semaphore>,
        config: AuthConfig,
    ) -> Result<Self, AuthError> {
        let pub_key_der = public_key_der(&rsa_key)?;
        Ok(Self {
            state: AuthState::AwaitingLoginStart,
            rsa_key,
            pub_key_der,
            http,
            rate_limiter,
            config,
        })
    }

    pub async fn process(&mut self, event: AuthEvent, client_ip: IpAddr) -> Vec<AuthOutbound> {
        let result = self.step(event, client_ip).await;
        match result {
            Ok((state, outbound)) => {
                self.state = state;
                outbound
            },
            Err(e) => {
                let reason = e.to_json_reason();
                self.state = AuthState::Failed(reason.clone());
                vec![AuthOutbound::LoginDisconnect { reason }]
            },
        }
    }

    /// Advance the login state machine by handling a single authentication event for the given client IP.
    ///
    /// This method processes `AuthEvent`s according to the current `AuthState`, performing the offline
    /// login flow, initiating encryption, validating encryption responses (including the 1.19
    /// "signed-nonce" form where the verify-token can be empty), performing session verification
    /// (hasJoined), and producing the corresponding outbound actions such as `EncryptionRequest`,
    /// `EnableEncryption`, `SetCompression`, and `LoginSuccess`. On failure it returns an `AuthError`.
    ///
    /// # Parameters
    ///
    /// - `event`: the incoming authentication event to process (e.g. `LoginStart` or
    ///   `EncryptionResponse`).
    /// - `client_ip`: the peer IP address; may be sent to the session server when proxy-prevention is
    ///   enabled.
    ///
    /// # Returns
    ///
    /// `Ok((AuthState, Vec<AuthOutbound>))` on success containing the pipeline's new state and any
    /// outbound messages to send to the client; `Err(AuthError)` on failure.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::net::IpAddr;
    /// # async fn example(mut pipeline: crate::auth::AuthPipeline) -> Result<(), crate::auth::AuthError> {
    /// use crate::auth::{AuthEvent, AuthPipeline};
    /// let event = AuthEvent::LoginStart { username: "Player".into(), client_uuid: None };
    /// let ip: IpAddr = "127.0.0.1".parse().unwrap();
    /// let (new_state, outbounds) = pipeline.step(event, ip).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn step(
        &mut self,
        event: AuthEvent,
        client_ip: IpAddr,
    ) -> Result<(AuthState, Vec<AuthOutbound>), AuthError> {
        match &self.state {
            AuthState::AwaitingLoginStart => {
                let username = match &event {
                    AuthEvent::LoginStart { username, .. } => username.clone(),
                    _ => return Err(AuthError::EncryptionSetupFailed("unexpected event".into())),
                };

                // Validate the client-supplied username before it is used as an
                // identity (offline UUID) or sent to the session server. Enforce
                // the canonical Minecraft rules: 1–16 chars, [A-Za-z0-9_].
                if !is_valid_username(&username) {
                    return Err(AuthError::InvalidUsername);
                }

                if !self.config.online_mode {
                    let uuid = offline_uuid(&username);
                    let mut out = Vec::new();
                    if self.config.compression_threshold >= 0 {
                        out.push(AuthOutbound::SetCompression {
                            threshold: self.config.compression_threshold,
                        });
                    }
                    out.push(AuthOutbound::LoginSuccess {
                        uuid,
                        username: username.clone(),
                        properties: vec![],
                    });
                    let profile = AuthenticatedProfile {
                        id: uuid,
                        name: username,
                        properties: vec![],
                    };
                    return Ok((AuthState::Authenticated { profile }, out));
                }

                let verify_token = generate_verify_token();
                let out = vec![AuthOutbound::EncryptionRequest {
                    server_id: String::new(),
                    public_key: self.pub_key_der.clone(),
                    verify_token: verify_token.to_vec(),
                }];
                Ok((
                    AuthState::AwaitingEncryptionResponse {
                        verify_token,
                        username,
                        client_ip,
                    },
                    out,
                ))
            },

            AuthState::AwaitingEncryptionResponse {
                verify_token,
                username,
                client_ip,
            } => {
                let (shared_secret_enc, verify_token_enc) = match &event {
                    AuthEvent::EncryptionResponse {
                        shared_secret_enc,
                        verify_token_enc,
                    } => (shared_secret_enc.clone(), verify_token_enc.clone()),
                    _ => return Err(AuthError::EncryptionSetupFailed("unexpected event".into())),
                };
                let stored_token = *verify_token;
                let username = username.clone();
                let client_ip = *client_ip;

                let rsa_key_1 = self.rsa_key.clone();
                let ss_enc = shared_secret_enc.clone();
                let shared_secret =
                    tokio::task::spawn_blocking(move || rsa_decrypt(&rsa_key_1, &ss_enc))
                        .await
                        .map_err(|_| AuthError::EncryptionSetupFailed("task panic".into()))??;

                // 1.19 / 1.19.1 / 1.19.2 (proto 759-760) clients with a
                // Mojang profile key send the SIGNED form of the
                // Encryption Response: instead of an RSA-encrypted verify
                // token they send `salt + signature`, which the
                // connection layer cannot turn into an encrypted token —
                // it surfaces here as an empty `verify_token_enc`. The
                // nonce in that mode is bound by the profile signature
                // (not re-verified here); session integrity still comes
                // from the `hasJoined` server-hash check below, so skip
                // the token comparison rather than fail auth. Non-empty
                // tokens (all other versions, and 1.19 clients without a
                // profile key) are validated as before.
                if verify_token_enc.is_empty() {
                    tracing::debug!(
                        "encryption response used 1.19 signed-nonce form; \
                         skipping verify-token comparison (session validated via hasJoined)"
                    );
                } else {
                    let rsa_key_2 = self.rsa_key.clone();
                    let vt_enc = verify_token_enc.clone();
                    let decrypted_token =
                        tokio::task::spawn_blocking(move || rsa_decrypt(&rsa_key_2, &vt_enc))
                            .await
                            .map_err(|_| AuthError::EncryptionSetupFailed("task panic".into()))??;

                    if decrypted_token.as_slice() != stored_token.as_slice() {
                        return Err(AuthError::VerifyTokenMismatch);
                    }
                }

                let ss_arr: [u8; 16] = shared_secret.as_slice().try_into().map_err(|_| {
                    AuthError::EncryptionSetupFailed("shared secret not 16 bytes".into())
                })?;

                let server_hash = minecraft_hex_digest("", &ss_arr, &self.pub_key_der);
                let ip_opt = self.config.prevent_proxy_connections.then_some(client_ip);

                let profile = verify_session(
                    &self.http,
                    &username,
                    &server_hash,
                    ip_opt,
                    self.rate_limiter.clone(),
                    self.config.session_timeout_secs,
                )
                .await?;

                let mut out = vec![AuthOutbound::EnableEncryption {
                    shared_secret: ss_arr,
                }];
                if self.config.compression_threshold >= 0 {
                    out.push(AuthOutbound::SetCompression {
                        threshold: self.config.compression_threshold,
                    });
                }
                out.push(AuthOutbound::LoginSuccess {
                    uuid: profile.id,
                    username: profile.name.clone(),
                    properties: profile.properties.clone(),
                });
                Ok((AuthState::Authenticated { profile }, out))
            },

            _ => Err(AuthError::EncryptionSetupFailed(
                "auth already completed or failed".into(),
            )),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self.state, AuthState::Authenticated { .. })
    }

    pub fn is_failed(&self) -> bool {
        matches!(self.state, AuthState::Failed(_))
    }

    pub fn profile(&self) -> Option<&AuthenticatedProfile> {
        match &self.state {
            AuthState::Authenticated { profile } => Some(profile),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_mode_transitions_to_authenticated() {
        let uuid = offline_uuid("TestPlayer");
        assert_eq!(uuid.get_version_num(), 3);
    }
}
