//! Prometheus exposition endpoint.
//!
//! Tiny axum app that exposes `/metrics` in Prometheus text format
//! from the shared [`MetricsCollector`] registry. Lifetime tied to
//! the `[metrics] enabled = true` config flag; bound to
//! `[metrics] bind` (default `127.0.0.1:9090`).

use super::collector::MetricsCollector;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct MetricsExporter {
    collector: Arc<MetricsCollector>,
}

impl MetricsExporter {
    pub fn new(collector: Arc<MetricsCollector>) -> Self {
        Self { collector }
    }

    pub async fn serve(&self, bind: String) -> std::io::Result<()> {
        let app = axum::Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state(self.collector.clone());

        let listener = TcpListener::bind(&bind).await?;
        tracing::info!("Metrics server listening on {}", bind);

        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn metrics_handler(State(collector): State<Arc<MetricsCollector>>) -> Response {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = collector.get_registry().gather();

    match encoder.encode_to_string(&metric_families) {
        Ok(output) => output.into_response(),
        Err(e) => {
            tracing::error!("Failed to encode metrics: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to encode metrics",
            )
                .into_response()
        },
    }
}
