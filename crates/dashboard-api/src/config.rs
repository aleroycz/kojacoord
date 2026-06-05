use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,

    pub database: DatabaseConfig,

    pub s3: S3Config,

    pub jwt: JwtConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,

    #[serde(default = "default_pool")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub endpoint_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,

    #[serde(default = "default_jwt_exp")]
    pub expiry_hours: u64,
}

fn default_bind() -> String {
    // The dashboard API is an administrative interface and must not be exposed
    // publicly by default. Operators can opt in to an external bind explicitly.
    "127.0.0.1:3001".into()
}
fn default_pool() -> u32 {
    10
}
fn default_jwt_exp() -> u64 {
    24
}

/// Minimum acceptable length (in bytes) for the JWT signing secret.
const MIN_JWT_SECRET_LEN: usize = 32;

/// Well-known placeholder/example secrets that must never be used in practice.
const FORBIDDEN_JWT_SECRETS: &[&str] = &[
    "changeme",
    "change-me",
    "change_me",
    "secret",
    "default",
    "placeholder",
    "your-secret-key",
    "your_secret_key",
    "supersecret",
    "password",
];

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        use figment::{
            providers::{Env, Format, Toml},
            Figment,
        };
        let cfg: Self = Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed("DASH_").global())
            .extract()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate security-sensitive configuration. Fails fast on weak settings so
    /// the service refuses to start with an insecure JWT secret.
    fn validate(&self) -> anyhow::Result<()> {
        let secret = self.jwt.secret.trim();

        if secret.len() < MIN_JWT_SECRET_LEN {
            anyhow::bail!(
                "jwt.secret is too short ({} bytes); it must be at least {} bytes. \
                 Generate one with e.g. `openssl rand -base64 48`.",
                secret.len(),
                MIN_JWT_SECRET_LEN
            );
        }

        let lowered = secret.to_ascii_lowercase();
        if FORBIDDEN_JWT_SECRETS
            .iter()
            .any(|bad| lowered == *bad || lowered.contains(bad))
        {
            anyhow::bail!(
                "jwt.secret matches a well-known placeholder value; \
                 set a unique, randomly generated secret."
            );
        }

        Ok(())
    }
}
