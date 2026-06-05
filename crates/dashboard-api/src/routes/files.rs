use axum::{
    extract::{Multipart, Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    auth::{self, AuthUser},
    error::AppError,
    routes::AppState,
};

#[derive(Deserialize)]
pub struct FileQuery {
    pub prefix: Option<String>,
}

/// Sanitise a user-supplied S3 object name into a safe relative key.
///
/// Rejects path traversal (`..`), absolute/UNC/drive paths, backslashes, NUL
/// bytes, and any characters outside a conservative whitelist. Returns a
/// normalised forward-slash relative path with no leading slash.
fn sanitize_relative_key(input: &str) -> Result<String, AppError> {
    let trimmed = input.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("empty file name".into()));
    }
    if trimmed.contains('\\') || trimmed.contains('\0') || trimmed.contains(':') {
        return Err(AppError::BadRequest(
            "file name contains invalid path characters".into(),
        ));
    }

    let mut parts = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(AppError::BadRequest(
                "path traversal is not allowed in file names".into(),
            ));
        }
        if !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
        {
            return Err(AppError::BadRequest(
                "file name contains disallowed characters".into(),
            ));
        }
        parts.push(seg);
    }

    if parts.is_empty() {
        return Err(AppError::BadRequest("invalid file name".into()));
    }
    Ok(parts.join("/"))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerTemplateJson {
    pub name: String,
    #[serde(default)]
    pub docker_image: Option<String>,
    #[serde(default)]
    pub memory_mb: Option<i64>,
    #[serde(default)]
    pub cpu_quota: Option<i64>,
    #[serde(default)]
    pub max_players: Option<i32>,
    #[serde(default)]
    pub min_instances: Option<i32>,
    #[serde(default)]
    pub max_instances: Option<i32>,
    #[serde(default)]
    pub extra_env: Option<serde_json::Value>,
    #[serde(default)]
    pub jar_path: Option<String>,
}

pub async fn list_files(
    State(state): State<Arc<AppState>>,
    _auth: AuthUser,
    Query(q): Query<FileQuery>,
) -> Result<Json<Value>, AppError> {
    let prefix = q.prefix.unwrap_or_default();
    let files = state
        .s3
        .list(&prefix)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({"files": files})))
}

pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    auth::require_admin(&auth.0)?;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?
    {
        let name = field.name().unwrap_or("file").to_owned();
        // Enforce a fixed prefix and reject traversal/absolute paths so an
        // admin cannot write to arbitrary S3 keys.
        let safe_name = sanitize_relative_key(&name)?;
        let key = format!("uploads/{}", safe_name);
        let data = field
            .bytes()
            .await
            .map_err(|e| AppError::BadRequest(e.to_string()))?;
        state
            .s3
            .upload_bytes(&key, data.to_vec())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        tracing::info!(key = %key, bytes = data.len(), "file uploaded");
    }

    Ok(Json(json!({"status": "uploaded"})))
}

pub async fn delete_file(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(key): Path<String>,
) -> Result<Json<Value>, AppError> {
    auth::require_admin(&auth.0)?;
    state
        .s3
        .delete(&key)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    tracing::info!(key = %key, "file deleted");
    Ok(Json(json!({"deleted": key})))
}

pub async fn upload_server_files(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    auth::require_admin(&auth.0)?;

    let mut template_json: Option<ServerTemplateJson> = None;
    let mut server_files: HashMap<String, Vec<u8>> = HashMap::new();
    let server_prefix = format!("servers/{}", uuid::Uuid::new_v4());

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?
    {
        let name = field.name().unwrap_or("file").to_owned();
        let filename = field.file_name().map(|f| f.to_owned());
        let data = field
            .bytes()
            .await
            .map_err(|e| AppError::BadRequest(e.to_string()))?;

        if name == "template" || filename.as_deref() == Some("template.json") {
            let template_str = std::str::from_utf8(&data).map_err(|e| {
                AppError::BadRequest(format!("Invalid UTF-8 in template.json: {}", e))
            })?;
            template_json = Some(
                serde_json::from_str(template_str)
                    .map_err(|e| AppError::BadRequest(format!("Invalid template.json: {}", e)))?,
            );
            tracing::info!("Parsed template.json");
        } else {
            let raw_name = filename.as_deref().unwrap_or(&name);
            let safe_name = sanitize_relative_key(raw_name)?;
            let file_key = format!("{}/{}", server_prefix, safe_name);
            server_files.insert(file_key, data.to_vec());
        }
    }

    let template = template_json
        .ok_or_else(|| AppError::BadRequest("template.json is required".to_string()))?;

    for (key, data) in &server_files {
        state
            .s3
            .upload_bytes(key, data.clone())
            .await
            .map_err(|e| AppError::Internal(format!("Failed to upload {}: {}", key, e)))?;
        tracing::info!(key = %key, bytes = data.len(), "server file uploaded");
    }

    let jar_s3_key = if let Some(jar_path) = &template.jar_path {
        let jar_key = format!("{}/{}", server_prefix, jar_path);
        if server_files.contains_key(&jar_key) {
            Some(jar_key)
        } else {
            None
        }
    } else {
        server_files.keys().find(|k| k.ends_with(".jar")).cloned()
    };

    let result = sqlx::query(
        "INSERT INTO server_templates \
         (name, docker_image, jar_s3_key, memory_mb, cpu_quota, max_players, min_instances, max_instances, extra_env) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&template.name)
    .bind(template.docker_image.as_deref().unwrap_or("itzg/minecraft-server:latest"))
    .bind(&jar_s3_key)
    .bind(template.memory_mb.unwrap_or(2048))
    .bind(template.cpu_quota.unwrap_or(100000))
    .bind(template.max_players.unwrap_or(20))
    .bind(template.min_instances.unwrap_or(0))
    .bind(template.max_instances.unwrap_or(10))
    .bind(template.extra_env.map(|v| v.to_string()))
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to create template: {}", e)))?;

    tracing::info!(
        template_id = result.last_insert_id(),
        template_name = %template.name,
        jar_s3_key = ?jar_s3_key,
        files_count = server_files.len(),
        "server template created"
    );

    Ok(Json(json!({
        "status": "created",
        "template_id": result.last_insert_id(),
        "template_name": template.name,
        "server_prefix": server_prefix,
        "files_uploaded": server_files.len(),
        "jar_s3_key": jar_s3_key
    })))
}
