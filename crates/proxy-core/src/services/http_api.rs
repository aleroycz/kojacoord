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
    let cors = tower_http::cors::CorsLayer::permissive();

    let dashboard_dir = "../../dashboard-ui/dist";
    let dashboard_service = ServeDir::new(dashboard_dir).fallback(
        ServeDir::new(dashboard_dir)
            .fallback(ServeDir::new(dashboard_dir).fallback(ServeDir::new(dashboard_dir))),
    );

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/players", get(players))
        .route("/api/ban", post(ban))
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
        .map(|t| t == token)
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
    let players_online = proxy.sessions.read().await.len();

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

    let sessions = st.proxy.sessions.read().await;
    let mut list = Vec::with_capacity(sessions.len());
    for (uuid, sess) in sessions.iter() {
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

    let reason = req
        .reason
        .unwrap_or_else(|| "Banned by an operator".to_owned());
    let banned_by = req.banned_by.unwrap_or_else(|| "dashboard".to_owned());

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
