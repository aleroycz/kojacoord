use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{
    auth::{self, AuthUser},
    db,
    error::AppError,
    routes::AppState,
};

#[derive(sqlx::FromRow)]
struct PlayerBanRow {
    id: i64,
    reason: String,
    banned_by: String,
    banned_at: Option<chrono::NaiveDateTime>,
    expires_at: Option<chrono::NaiveDateTime>,
    active: i8,
}

#[derive(sqlx::FromRow)]
struct ActiveBanRow {
    id: i64,
    player_uuid: String,
    username: Option<String>,
    reason: String,
    banned_by: String,
    banned_at: Option<chrono::NaiveDateTime>,
    expires_at: Option<chrono::NaiveDateTime>,
}

#[derive(Deserialize)]
pub struct Pagination {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub async fn list_players(
    State(state): State<Arc<AppState>>,
    _auth: AuthUser,
    Query(p): Query<Pagination>,
) -> Result<Json<Value>, AppError> {
    let players =
        db::list_players(&state.pool, p.limit.unwrap_or(50), p.offset.unwrap_or(0)).await?;

    let mut online: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    {
        for entry in state.proxy.sessions.iter() {
            let uuid = entry.key();
            let sess = entry.value();
            if let Ok(s) = sess.try_read() {
                online.insert(uuid.hyphenated().to_string(), s.current_server.clone());
            }
        }
    }

    let enriched: Vec<Value> = players
        .iter()
        .map(|pl| {
            let live = online.get(&pl.uuid);
            json!({
                "id":             pl.id,
                "uuid":           pl.uuid,
                "username":       pl.username,
                "rank":           pl.rank,
                "metadata":       pl.metadata,
                "online":         live.is_some(),
                "current_server": live.and_then(|s| s.clone()),
            })
        })
        .collect();

    Ok(Json(json!(enriched)))
}

#[derive(Deserialize)]
pub struct KickBody {
    pub reason: String,
}

#[derive(Deserialize)]
pub struct BanBody {
    pub reason: String,
    pub duration_hours: Option<i64>,
}

pub async fn kick_player(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(uuid): Path<String>,
    Json(body): Json<KickBody>,
) -> Result<Json<Value>, AppError> {
    auth::require_moderator(&auth.0)?;

    let mut reason = body.reason.clone();
    reason.truncate(1024);

    sqlx::query("INSERT INTO player_kicks (player_uuid, reason, kicked_by) VALUES (?, ?, ?)")
        .bind(&uuid)
        .bind(&reason)
        .bind(&auth.0.sub)
        .execute(&state.pool)
        .await?;

    if let Ok(target) = uuid::Uuid::parse_str(&uuid) {
        let kick_json = json!({
            "text": format!("You were kicked: {}", reason),
            "color": "red"
        })
        .to_string();
        state.proxy.kick_player(&target, &kick_json).await;
    }

    tracing::info!(by = %auth.0.sub, player = %uuid, "Player kicked");
    Ok(Json(json!({"kicked": true})))
}

pub async fn ban_player(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(uuid): Path<String>,
    Json(body): Json<BanBody>,
) -> Result<Json<Value>, AppError> {
    auth::require_moderator(&auth.0)?;

    let expires_at = body
        .duration_hours
        .map(|h| chrono::Utc::now() + chrono::Duration::hours(h));

    let mut reason = body.reason.clone();
    reason.truncate(1024);

    let ban_id = sqlx::query(
        "INSERT INTO player_bans (player_uuid, reason, banned_by, expires_at, active) \
         VALUES (?, ?, ?, ?, 1)",
    )
    .bind(&uuid)
    .bind(&reason)
    .bind(&auth.0.sub)
    .bind(expires_at)
    .execute(&state.pool)
    .await?
    .last_insert_id();

    let _ = sqlx::query("UPDATE players SET `rank`='BANNED' WHERE uuid=?")
        .bind(&uuid)
        .execute(&state.pool)
        .await;

    if let Ok(target) = uuid::Uuid::parse_str(&uuid) {
        let kick_json = json!({
            "text": format!("You have been banned: {}", reason),
            "color": "red"
        })
        .to_string();
        state.proxy.kick_player(&target, &kick_json).await;
    }

    tracing::info!(by = %auth.0.sub, player = %uuid, "Player banned");
    Ok(Json(json!({"banned": true, "ban_id": ban_id})))
}

pub async fn unban_player(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(uuid): Path<String>,
) -> Result<Json<Value>, AppError> {
    auth::require_moderator(&auth.0)?;
    sqlx::query("UPDATE player_bans SET active=0 WHERE player_uuid=? AND active=1")
        .bind(&uuid)
        .execute(&state.pool)
        .await?;

    let _ = sqlx::query("UPDATE players SET `rank`='DEFAULT' WHERE uuid=? AND `rank`='BANNED'")
        .bind(&uuid)
        .execute(&state.pool)
        .await;

    Ok(Json(json!({"unbanned": true})))
}

pub async fn list_player_bans(
    State(state): State<Arc<AppState>>,
    _auth: AuthUser,
    Path(uuid): Path<String>,
) -> Result<Json<Value>, AppError> {
    let rows = sqlx::query_as::<_, PlayerBanRow>(
        "SELECT id, reason, banned_by, banned_at, expires_at, active \
         FROM player_bans WHERE player_uuid=? ORDER BY banned_at DESC",
    )
    .bind(&uuid)
    .fetch_all(&state.pool)
    .await?;

    let bans: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id":        r.id,
                "reason":    r.reason,
                "banned_by": r.banned_by,
                "banned_at": r.banned_at,
                "expires_at":r.expires_at,
                "active":    r.active,
            })
        })
        .collect();

    Ok(Json(json!(bans)))
}

pub async fn list_active_bans(
    State(state): State<Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Value>, AppError> {
    let rows = sqlx::query_as::<_, ActiveBanRow>(
        "SELECT b.id, b.player_uuid, p.username, b.reason, b.banned_by, b.banned_at, b.expires_at \
         FROM player_bans b \
         LEFT JOIN players p ON p.uuid=b.player_uuid \
         WHERE b.active=1 AND (b.expires_at IS NULL OR b.expires_at > NOW()) \
         ORDER BY b.banned_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    let bans: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id":        r.id,
                "uuid":      r.player_uuid,
                "username":  r.username,
                "reason":    r.reason,
                "banned_by": r.banned_by,
                "banned_at": r.banned_at,
                "expires_at":r.expires_at,
            })
        })
        .collect();

    Ok(Json(json!(bans)))
}
