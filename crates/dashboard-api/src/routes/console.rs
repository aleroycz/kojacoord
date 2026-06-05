use axum::{
    extract::ws::{Message, WebSocket},
    extract::{Path, Query, State, WebSocketUpgrade},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;

use crate::{auth, error::AppError, routes::AppState};

#[derive(Deserialize)]
pub struct ConsoleAuth {
    /// JWT passed as a query parameter because browsers cannot set the
    /// `Authorization` header on a WebSocket handshake.
    pub token: Option<String>,
}

pub async fn console_ws(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Path(server_id): Path<i64>,
    Query(q): Query<ConsoleAuth>,
) -> Response {
    // Console access grants arbitrary command execution on the backend server,
    // so it is gated to administrators. Authenticate BEFORE upgrading the
    // socket; reject anonymous or under-privileged callers.
    let token = match q.token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return AppError::Unauthorized.into_response(),
    };
    let claims = match auth::authorize(&state, token) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = auth::require_admin(&claims) {
        return e.into_response();
    }

    tracing::info!(server_id, admin = %claims.sub, "console session authorized");
    ws.on_upgrade(move |socket| handle_console_ws(socket, state, server_id))
}

async fn handle_console_ws(mut socket: WebSocket, state: Arc<AppState>, server_id: i64) {
    let server: Option<crate::db::Server> = sqlx::query_as("SELECT * FROM servers WHERE id = ?")
        .bind(server_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    let Some(server) = server else {
        let _ = socket
            .send(Message::Text(r#"{"error":"server not found"}"#.into()))
            .await;
        return;
    };

    let Some(addr) = server.address else {
        let _ = socket
            .send(Message::Text(r#"{"error":"server has no address"}"#.into()))
            .await;
        return;
    };

    let port = server.port.unwrap_or(25566);
    let console_url = format!("ws://{}:{}/ws/console", addr, port as u32 + 1000);
    tracing::info!(server_id, %console_url, "connecting to upstream console");

    match tokio_tungstenite::connect_async(&console_url).await {
        Ok((upstream, _)) => {
            let (mut ws_tx, mut ws_rx) = socket.split();
            let (mut up_tx, mut up_rx) = upstream.split();

            let relay_down = tokio::spawn(async move {
                while let Some(Ok(msg)) = up_rx.next().await {
                    let txt = match msg.to_text() {
                        Ok(t) => t.to_owned(),
                        Err(_) => continue,
                    };
                    if ws_tx.send(Message::Text(txt)).await.is_err() {
                        break;
                    }
                }
            });

            while let Some(Ok(msg)) = ws_rx.next().await {
                if let Message::Text(cmd) = msg {
                    if up_tx
                        .send(tokio_tungstenite::tungstenite::Message::Text(cmd))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }

            relay_down.abort();
        },
        Err(e) => {
            tracing::warn!(server_id, error = %e, "failed to connect to upstream console");
            let _ = socket
                .send(Message::Text(format!(r#"{{"error":"{}"}}"#, e)))
                .await;
        },
    }
}
