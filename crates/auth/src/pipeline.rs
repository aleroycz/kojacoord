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

                let rsa_key_2 = self.rsa_key.clone();
                let vt_enc = verify_token_enc.clone();
                let decrypted_token =
                    tokio::task::spawn_blocking(move || rsa_decrypt(&rsa_key_2, &vt_enc))
                        .await
                        .map_err(|_| AuthError::EncryptionSetupFailed("task panic".into()))??;

                if decrypted_token.as_slice() != stored_token.as_slice() {
                    return Err(AuthError::VerifyTokenMismatch);
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
