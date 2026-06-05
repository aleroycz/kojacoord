use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("RSA decryption failed: {0}")]
    RsaDecryptionFailed(rsa::errors::Error),

    #[error("verify token mismatch — possible MITM attack")]
    VerifyTokenMismatch,

    #[error("session server unreachable: {0}")]
    SessionServerUnreachable(reqwest::Error),

    #[error("session server rejected authentication (HTTP 204 — session not found)")]
    SessionServerRejected,

    #[error("session server returned unexpected HTTP {0}")]
    SessionServerError(u16),

    #[error("malformed profile from session server: {0}")]
    MalformedProfile(serde_json::Error),

    #[error("Mojang API rate limit reached")]
    RateLimited,

    #[error("cipher initialization failed: {0}")]
    EncryptionSetupFailed(String),

    #[error("invalid username")]
    InvalidUsername,
}

impl AuthError {
    pub fn to_json_reason(&self) -> String {
        let text = match self {
            Self::SessionServerRejected => "Failed to verify username!",
            Self::RateLimited => "Authentication servers are busy. Please try again.",
            Self::SessionServerUnreachable(_) => "Could not reach authentication servers.",
            Self::InvalidUsername => "Invalid username.",
            _ => "Authentication failed.",
        };
        serde_json::json!({"text": text, "color": "red"}).to_string()
    }
}
