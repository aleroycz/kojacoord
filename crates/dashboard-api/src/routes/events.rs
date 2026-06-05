use axum::{
    extract::{Query, State},
    response::{sse::Event, Sse},
    Json,
};
use futures_util::stream::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{convert::Infallible, sync::Arc};
use tokio_stream::wrappers::BroadcastStream;

use crate::{auth, error::AppError, events::DashboardEvent, routes::AppState};

#[derive(Deserialize)]
pub struct EventsAuth {
    /// JWT passed as a query parameter because browser `EventSource` clients
    /// cannot set the `Authorization` header.
    pub token: Option<String>,
}

pub async fn sse_events(
    State(state): State<Arc<AppState>>,
    Query(q): Query<EventsAuth>,
) -> Result<Sse<impl futures_util::stream::Stream<Item = Result<Event, Infallible>>>, AppError> {
    // The event bus streams player PII and live network activity, so require a
    // valid token before subscribing an anonymous client.
    let token = q
        .token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or(AppError::Unauthorized)?;
    auth::authorize(&state, token)?;

    let rx = state.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| async move {
        result
            .ok()
            .and_then(|event| event.to_sse_event().ok().map(Ok))
    });
    Ok(Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default()))
}

#[derive(Deserialize)]
pub struct WrongModpackBody {
    pub player_uuid: String,
    pub player_name: String,
    pub server: String,
    pub required_modpack: String,
    pub client_modpack: String,
}

pub async fn wrong_modpack_event(
    State(state): State<Arc<AppState>>,
    Json(body): Json<WrongModpackBody>,
) -> Result<Json<Value>, AppError> {
    state.event_bus.publish(DashboardEvent::WrongModpack {
        player_uuid: body.player_uuid.clone(),
        player_name: body.player_name,
        server: body.server,
        required_modpack: body.required_modpack,
        client_modpack: body.client_modpack,
    });
    tracing::warn!(player = %body.player_uuid, "Wrong modpack event published");
    Ok(Json(json!({"ok": true})))
}
