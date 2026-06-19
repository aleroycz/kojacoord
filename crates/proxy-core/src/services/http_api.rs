//! HTTP management API.
//!
//! Operator-facing JSON API: list players, query backends, push
//! bans, view metrics. Bound to `[http_api] bind` (default
//! `127.0.0.1:8080`) and gated on a bearer token from
//! `[http_api] auth_token`. Use a reverse proxy for TLS — this
//! listener speaks plain HTTP by design.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use tower_http::services::ServeDir;
use uuid::Uuid;

use crate::proxy::ProxyState;

#[derive(Clone)]
struct ApiState {
    proxy: Arc<ProxyState>,
    token: String,
}

pub async fn serve(proxy: Arc<ProxyState>, bind: String, token: String) -> anyhow::Result<()> {
    // The dashboard UI is served same-origin from this listener, so no
    // cross-origin access is required. Restrict to the methods/headers actually
    // used and do NOT reflect arbitrary origins (was previously `permissive()`,
    // which allowed any site to drive the token-authenticated API).
    let cors = tower_http::cors::CorsLayer::new()
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ]);

    let dashboard_dir = "../../dashboard-ui/dist";
    let dashboard_service = ServeDir::new(dashboard_dir).fallback(
        ServeDir::new(dashboard_dir)
            .fallback(ServeDir::new(dashboard_dir).fallback(ServeDir::new(dashboard_dir))),
    );

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/players", get(players))
        .route("/api/ban", post(ban))
        .route("/api/warn", post(warn))
        .route("/api/mute", post(mute))
        .route("/api/unmute", post(unmute))
        .route("/api/purchase", post(purchase))
        .nest_service("/", dashboard_service)
        .layer(cors)
        .with_state(ApiState { proxy, token });

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("HTTP API listening on {}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| crate::services::constant_time_eq(t.as_bytes(), token.as_bytes()))
        .unwrap_or(false)
}

async fn health(State(st): State<ApiState>) -> impl IntoResponse {
    let proxy = &st.proxy;

    let db_configured = proxy.db.is_some();
    let db_healthy = match &proxy.db {
        Some(db) => db.ping().await.is_ok(),
        None => false,
    };

    let backends = proxy.server_registry.all();
    let backends_online = backends.iter().filter(|b| b.is_online()).count();
    let players_online = proxy.sessions.len();

    let healthy = backends_online > 0 && (!db_configured || db_healthy);

    let body = json!({
        "status": if healthy { "healthy" } else { "degraded" },
        "uptime_secs": proxy.started_at.elapsed().as_secs(),
        "players_online": players_online,
        "features": {
            "database":   { "configured": db_configured, "healthy": db_healthy },
            "backends":   { "online": backends_online, "total": backends.len(), "healthy": backends_online > 0 },
            "auth":       { "online_mode": proxy.config.proxy.online_mode, "healthy": true },
            "listeners":  { "bind": proxy.config.proxy.bind, "healthy": true },
            "permissions":{ "roles": proxy.roles.len(), "healthy": !proxy.roles.is_empty() },
        }
    });

    let code = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body))
}

async fn players(State(st): State<ApiState>, headers: HeaderMap) -> impl IntoResponse {
    if !authorized(&headers, &st.token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        );
    }

    let mut list = Vec::with_capacity(st.proxy.sessions.len());
    for entry in st.proxy.sessions.iter() {
        let sess = entry.value();
        let uuid = entry.key();
        if let Ok(s) = sess.try_read() {
            list.push(json!({
                "uuid": uuid.hyphenated().to_string(),
                "username": s.username,
                "server": s.current_server,
                "rank": s.rank,
                "protocol": s.protocol_version,
            }));
        }
    }
    (StatusCode::OK, Json(json!({ "players": list })))
}

#[derive(Deserialize)]
struct BanRequest {
    uuid: Option<String>,
    username: Option<String>,
    reason: Option<String>,
    banned_by: Option<String>,
}

async fn ban(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<BanRequest>,
) -> impl IntoResponse {
    if !authorized(&headers, &st.token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        );
    }
    let Some(db) = &st.proxy.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "no database" })),
        );
    };

    let uuid = match (&req.uuid, &req.username) {
        (Some(u), _) => Uuid::parse_str(u).ok(),
        (None, Some(name)) => db.uuid_for_username(name).await.ok().flatten(),
        _ => None,
    };
    let Some(uuid) = uuid else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "player not found" })),
        );
    };

    let mut reason = req
        .reason
        .unwrap_or_else(|| "Banned by an operator".to_owned());
    if reason.len() > 1024 {
        reason = reason
            .char_indices()
            .take_while(|(idx, _)| *idx < 1024)
            .map(|(_, c)| c)
            .collect();
    }

    let mut banned_by = req.banned_by.unwrap_or_else(|| "dashboard".to_owned());
    if banned_by.len() > 256 {
        banned_by = banned_by
            .char_indices()
            .take_while(|(idx, _)| *idx < 256)
            .map(|(_, c)| c)
            .collect();
    }

    if let Err(e) = db.insert_ban(uuid, &reason, &banned_by, None).await {
        tracing::warn!(error = %e, "dashboard ban failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "db error" })),
        );
    }

    let kick_json = serde_json::json!({
        "text": format!("You have been banned: {}", reason),
        "color": "red"
    })
    .to_string();
    st.proxy.kick_player(&uuid, &kick_json).await;

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "uuid": uuid.hyphenated().to_string() })),
    )
}

/// Resolve a sanction target from an explicit UUID or a username lookup.
async fn resolve_target(
    db: &crate::db::Db,
    uuid: &Option<String>,
    username: &Option<String>,
) -> Option<Uuid> {
    match (uuid, username) {
        (Some(u), _) => Uuid::parse_str(u).ok(),
        (None, Some(name)) => db.uuid_for_username(name).await.ok().flatten(),
        _ => None,
    }
}

/// Truncate a string to at most `max` bytes on a char boundary.
fn clamp_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        s = s
            .char_indices()
            .take_while(|(idx, _)| *idx < max)
            .map(|(_, c)| c)
            .collect();
    }
    s
}

#[derive(Deserialize)]
struct WarnRequest {
    uuid: Option<String>,
    username: Option<String>,
    reason: Option<String>,
    warned_by: Option<String>,
}

/// Record a warning and, if the player is online, deliver the reason to them.
async fn warn(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<WarnRequest>,
) -> impl IntoResponse {
    if !authorized(&headers, &st.token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        );
    }
    let Some(db) = &st.proxy.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "no database" })),
        );
    };

    let Some(uuid) = resolve_target(db, &req.uuid, &req.username).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "player not found" })),
        );
    };

    let reason = clamp_to(
        req.reason
            .unwrap_or_else(|| "Warned by an operator".to_owned()),
        1024,
    );
    let warned_by = clamp_to(req.warned_by.unwrap_or_else(|| "dashboard".to_owned()), 256);

    if let Err(e) = db.insert_warning(uuid, &reason, &warned_by).await {
        tracing::warn!(error = %e, "dashboard warn failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "db error" })),
        );
    }

    // Notify the player if they're online so the warning lands immediately.
    st.proxy
        .send_system_message_to(&uuid, &format!("§e§lWarning: §r§7{}", reason))
        .await;

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "uuid": uuid.hyphenated().to_string() })),
    )
}

#[derive(Deserialize)]
struct MuteRequest {
    uuid: Option<String>,
    username: Option<String>,
    reason: Option<String>,
    muted_by: Option<String>,
    /// Mute duration in seconds. Omitted, zero, or negative → permanent.
    duration_secs: Option<i64>,
}

/// Mute a player's chat. The mute is persisted, applied to the live
/// session (so the relay enforces it without a DB hit per message), and
/// the player is notified of the duration.
async fn mute(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<MuteRequest>,
) -> impl IntoResponse {
    if !authorized(&headers, &st.token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        );
    }
    let Some(db) = &st.proxy.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "no database" })),
        );
    };

    let Some(uuid) = resolve_target(db, &req.uuid, &req.username).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "player not found" })),
        );
    };

    let reason = clamp_to(
        req.reason
            .unwrap_or_else(|| "Muted by an operator".to_owned()),
        1024,
    );
    let muted_by = clamp_to(req.muted_by.unwrap_or_else(|| "dashboard".to_owned()), 256);

    // Positive duration → timed mute; anything else → permanent.
    let expires_at = match req.duration_secs {
        Some(secs) if secs > 0 => {
            Some(chrono::Utc::now().naive_utc() + chrono::Duration::seconds(secs))
        },
        _ => None,
    };

    if let Err(e) = db.insert_mute(uuid, &reason, &muted_by, expires_at).await {
        tracing::warn!(error = %e, "dashboard mute failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "db error" })),
        );
    }

    // Apply to the live session and notify the player, if online.
    let mute_state = crate::session::MuteState {
        reason: reason.clone(),
        expires_at,
    };
    if let Some(sess) = st.proxy.sessions.get(&uuid) {
        sess.write().await.mute = Some(mute_state.clone());
    }
    let notice = crate::relay::build_mute_notice(&mute_state);
    st.proxy.send_system_message_to(&uuid, &notice).await;

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "uuid": uuid.hyphenated().to_string(),
            "permanent": expires_at.is_none(),
        })),
    )
}

#[derive(Deserialize)]
struct UnmuteRequest {
    uuid: Option<String>,
    username: Option<String>,
}

/// Lift a player's mute: clear it in the DB and the live session.
async fn unmute(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<UnmuteRequest>,
) -> impl IntoResponse {
    if !authorized(&headers, &st.token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        );
    }
    let Some(db) = &st.proxy.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "no database" })),
        );
    };

    let Some(uuid) = resolve_target(db, &req.uuid, &req.username).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "player not found" })),
        );
    };

    if let Err(e) = db.clear_mute(uuid).await {
        tracing::warn!(error = %e, "dashboard unmute failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "db error" })),
        );
    }

    if let Some(sess) = st.proxy.sessions.get(&uuid) {
        sess.write().await.mute = None;
    }
    st.proxy
        .send_system_message_to(&uuid, "§aYour mute has been lifted.")
        .await;

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "uuid": uuid.hyphenated().to_string() })),
    )
}

#[derive(Deserialize)]
struct PurchaseRequest {
    username: String,
    product_slug: String,
}

async fn purchase(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<PurchaseRequest>,
) -> impl IntoResponse {
    if !authorized(&headers, &st.token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        );
    }
    let Some(db) = &st.proxy.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "no database" })),
        );
    };

    let username = req.username.trim();
    let product_slug = req.product_slug.trim();

    if username.is_empty() || product_slug.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "username and product_slug are required" })),
        );
    }

    let mut online_uuid = None;
    for entry in st.proxy.sessions.iter() {
        let sess = entry.value();
        if let Ok(s) = sess.try_read() {
            if s.username.eq_ignore_ascii_case(username) {
                online_uuid = Some(*entry.key());
                break;
            }
        }
    }

    let purchase_id = match db.add_pending_purchase(username, product_slug).await {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, "Failed to record pending purchase in db");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "db error" })),
            );
        },
    };

    let mut delivered = false;
    if let Some(uuid) = online_uuid {
        if let Some(tx) = st.proxy.backend_outbound.get(&uuid) {
            let proto = if let Some(sess) = st.proxy.sessions.get(&uuid) {
                if let Ok(s) = sess.try_read() {
                    s.protocol_version
                } else {
                    47
                }
            } else {
                47
            };
            let payload = product_slug.as_bytes();
            let pkt_raw = crate::packet_builder::build_serverbound_plugin_message_packet(
                "kojacoord:purchase",
                payload,
                proto,
            );
            if tx.send(pkt_raw).is_ok() {
                let _ = db.mark_purchase_delivered(purchase_id).await;
                delivered = true;
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "delivered": delivered })),
    )
}
