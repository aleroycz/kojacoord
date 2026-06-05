use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{
    auth::{self, AuthUser},
    db,
    error::AppError,
    modpack::ModpackDownloader,
    routes::AppState,
};

#[derive(Deserialize, Serialize)]
pub struct CreateTemplateBody {
    pub name: String,
    pub game_type: Option<String>,
    pub image: Option<String>,
    pub memory_mb: Option<i64>,
    pub max_players: Option<i32>,
    pub min_instances: Option<i32>,
    pub modpack_source: Option<String>,
    pub modrinth_project_id: Option<String>,
    pub modrinth_version_id: Option<String>,
    pub curseforge_project_id: Option<u32>,
    pub curseforge_file_id: Option<u32>,
}

#[derive(sqlx::FromRow)]
struct ModpackStatusRow {
    modpack_status: Option<String>,
    modpack_id: Option<String>,
    modpack_loader: Option<String>,
}

pub async fn list_templates(
    State(state): State<Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Value>, AppError> {
    let rows = db::list_templates(&state.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let templates: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id":                r.id,
                "name":              r.name,
                "game_type":         r.game_type,
                "image":             r.image,
                "memory_mb":         r.memory_mb,
                "max_players":       r.max_players,
                "min_instances":     r.min_instances,
                "modpack_id":        r.modpack_id,
                "modpack_loader":    r.modpack_loader,
                "modpack_mc_version": r.modpack_mc_version,
                "modpack_status":    r.modpack_status,
                "modpack_source":    r.modpack_source,
            })
        })
        .collect();

    Ok(Json(json!(templates)))
}

pub async fn create_template(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Json(body): Json<CreateTemplateBody>,
) -> Result<Json<Value>, AppError> {
    auth::require_admin(&auth.0)?;

    let result = sqlx::query(
        "INSERT INTO server_templates \
         (name, game_type, image, memory_mb, max_players, min_instances, modpack_source) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&body.name)
    .bind(&body.game_type)
    .bind(
        body.image
            .as_deref()
            .unwrap_or("itzg/minecraft-server:latest"),
    )
    .bind(body.memory_mb.unwrap_or(1024))
    .bind(body.max_players.unwrap_or(20))
    .bind(body.min_instances.unwrap_or(0))
    .bind(&body.modpack_source)
    .execute(&state.pool)
    .await?;

    Ok(Json(
        json!({"id": result.last_insert_id(), "name": body.name}),
    ))
}

pub async fn update_template(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<i64>,
    Json(body): Json<CreateTemplateBody>,
) -> Result<Json<Value>, AppError> {
    auth::require_admin(&auth.0)?;

    // Validate template exists using db module
    let templates = db::list_templates(&state.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !templates.iter().any(|t| t.id == id) {
        return Err(AppError::NotFound(format!("template {}", id)));
    }

    sqlx::query(
        "UPDATE server_templates SET \
         name=?, game_type=?, image=?, memory_mb=?, max_players=?, min_instances=?, modpack_source=? \
         WHERE id=?",
    )
    .bind(&body.name)
    .bind(&body.game_type)
    .bind(&body.image)
    .bind(body.memory_mb)
    .bind(body.max_players)
    .bind(body.min_instances)
    .bind(&body.modpack_source)
    .bind(id)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({"updated": true})))
}

pub async fn delete_template(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    auth::require_superadmin(&auth.0)?;

    sqlx::query("DELETE FROM server_templates WHERE id=?")
        .bind(id)
        .execute(&state.pool)
        .await?;

    Ok(Json(json!({"deleted": true})))
}

pub async fn download_modpack(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<i64>,
    Json(body): Json<CreateTemplateBody>,
) -> Result<Json<Value>, AppError> {
    auth::require_admin(&auth.0)?;

    let task_id = uuid::Uuid::new_v4().to_string();
    let tid = task_id.clone();
    let pool = state.pool.clone();
    let s3 = state.s3.clone();
    let http = reqwest::Client::new();

    tokio::spawn(async move {
        let downloader = ModpackDownloader::new(http, s3);
        let result = match body.modpack_source.as_deref() {
            Some("modrinth") => {
                let project_id = body.modrinth_project_id.as_deref().unwrap_or("");
                let version_id = body.modrinth_version_id.as_deref().unwrap_or("");
                downloader
                    .download_modrinth(&body.name, project_id, version_id)
                    .await
            },
            Some("curseforge") => {
                let project_id = body.curseforge_project_id.unwrap_or(0);
                let file_id = body.curseforge_file_id.unwrap_or(0);
                // The CurseForge API key is a server-side secret and must never
                // be accepted from client requests. Source it from the env.
                let api_key = match std::env::var("CURSEFORGE_API_KEY") {
                    Ok(key) if !key.trim().is_empty() => key,
                    _ => {
                        tracing::error!(
                            "CURSEFORGE_API_KEY is not configured; cannot download CurseForge modpack"
                        );
                        return;
                    },
                };
                downloader
                    .download_curseforge(&body.name, project_id, file_id, &api_key)
                    .await
            },
            _ => {
                return;
            },
        };

        match result {
            Ok(info) => {
                let _ = sqlx::query(
                    "UPDATE server_templates SET \
                     modpack_id=?, modpack_loader=?, modpack_mc_version=?, modpack_status='ready' \
                     WHERE id=?",
                )
                .bind(&info.name)
                .bind(&info.loader)
                .bind(&info.minecraft_version)
                .bind(id)
                .execute(&pool)
                .await;
                tracing::info!("Modpack download complete for template {}", id);
            },
            Err(e) => {
                let _ =
                    sqlx::query("UPDATE server_templates SET modpack_status='error' WHERE id=?")
                        .bind(id)
                        .execute(&pool)
                        .await;
                tracing::error!("Modpack download failed: {}", e);
            },
        }
    });

    Ok(Json(json!({"status": "downloading", "task_id": tid})))
}

pub async fn modpack_status(
    State(state): State<Arc<AppState>>,
    _auth: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let row = sqlx::query_as::<_, ModpackStatusRow>(
        "SELECT modpack_status, modpack_id, modpack_loader FROM server_templates WHERE id=?",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("template {}", id)))?;

    Ok(Json(json!({
        "status":    row.modpack_status,
        "modpack_id": row.modpack_id,
        "loader":    row.modpack_loader,
    })))
}
