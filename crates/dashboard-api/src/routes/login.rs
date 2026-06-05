use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::{auth, db, error::AppError, routes::AppState};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,

    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,

    pub role: String,
}

/// Maximum consecutive failed attempts before an account is temporarily locked.
const MAX_FAILED_ATTEMPTS: u32 = 5;
/// How long an account stays locked after exceeding the failure threshold.
const LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Failure counters reset if no attempt is seen within this window.
const ATTEMPT_WINDOW: Duration = Duration::from_secs(15 * 60);

/// A bcrypt hash of a fixed value, generated once at runtime so it is always a
/// valid hash of the configured cost. Used to perform a constant-cost
/// verification when the requested account does not exist, keeping the response
/// time of "unknown user" comparable to "wrong password" and preventing
/// username enumeration via timing.
fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| {
        bcrypt::hash("anti-enumeration-placeholder", bcrypt::DEFAULT_COST).unwrap_or_else(|_| {
            "$2b$12$.invalidbutnonemptyplaceholderhashvalue000000000000000".into()
        })
    })
}

#[derive(Default)]
struct Attempt {
    failures: u32,
    first_seen: Option<Instant>,
    locked_until: Option<Instant>,
}

fn attempts() -> &'static Mutex<HashMap<String, Attempt>> {
    static ATTEMPTS: OnceLock<Mutex<HashMap<String, Attempt>>> = OnceLock::new();
    ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns `Err` if the account is currently locked out.
fn check_locked(key: &str) -> Result<(), AppError> {
    let mut map = attempts().lock().unwrap();
    if let Some(a) = map.get_mut(key) {
        let now = Instant::now();
        if let Some(until) = a.locked_until {
            if now < until {
                return Err(AppError::TooManyRequests(
                    "account temporarily locked due to repeated failed logins".into(),
                ));
            }
            // Lock expired — reset.
            *a = Attempt::default();
        }
    }
    Ok(())
}

fn record_failure(key: &str) {
    let mut map = attempts().lock().unwrap();
    let now = Instant::now();
    let a = map.entry(key.to_owned()).or_default();
    match a.first_seen {
        Some(t) if now.duration_since(t) > ATTEMPT_WINDOW => {
            *a = Attempt::default();
            a.first_seen = Some(now);
        },
        None => a.first_seen = Some(now),
        _ => {},
    }
    a.failures += 1;
    if a.failures >= MAX_FAILED_ATTEMPTS {
        a.locked_until = Some(now + LOCKOUT);
    }
}

fn record_success(key: &str) {
    attempts().lock().unwrap().remove(key);
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let key = req.username.trim().to_ascii_lowercase();
    check_locked(&key)?;

    let user = db::find_admin(&state.pool, &req.username).await?;

    // Always run a bcrypt verification so the unknown-user and wrong-password
    // paths take comparable time (anti-enumeration). bcrypt::verify is run on a
    // blocking thread because it is CPU-intensive.
    let (hash, real_user) = match &user {
        Some(u) => (u.password_hash.clone(), true),
        None => (dummy_hash().to_owned(), false),
    };
    let password = req.password.clone();
    let valid =
        tokio::task::spawn_blocking(move || bcrypt::verify(&password, &hash).unwrap_or(false))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

    let user = match (real_user && valid, user) {
        (true, Some(u)) => u,
        _ => {
            record_failure(&key);
            return Err(AppError::Unauthorized);
        },
    };

    record_success(&key);
    db::update_last_login(&state.pool, user.id).await?;

    let token = auth::create_token(
        &user.username,
        &user.role,
        &state.cfg.jwt.secret,
        state.cfg.jwt.expiry_hours,
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(LoginResponse {
        token,
        role: user.role,
    }))
}
