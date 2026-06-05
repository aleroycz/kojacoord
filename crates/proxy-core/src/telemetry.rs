//! Anonymous, opt-out usage telemetry.
//!
//! When `[telemetry] enabled = true` (the default), the proxy periodically posts
//! coarse, non-identifying metrics to the Kojacoord metrics endpoint so we can
//! understand adoption. It sends only:
//!   - a stable instance id (the server_id; the endpoint salts + hashes it),
//!   - the proxy version, OS and architecture,
//!   - the peak online player count and the number of configured backends.
//!
//! It never sends IPs, hostnames, server names, or player identities. Setting
//! `[telemetry] enabled = false` disables it entirely — the endpoint is never
//! contacted.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::proxy::ProxyState;

#[derive(Serialize)]
struct TelemetryPayload<'a> {
    instance_id: &'a str,
    version: &'a str,
    os: &'a str,
    arch: &'a str,
    player_peak: i32,
    backend_count: i32,
}

/// Spawn the background telemetry task. No-op (with a log line) when disabled.
pub fn spawn(state: Arc<ProxyState>) {
    let cfg = state.config.telemetry.clone();
    if !cfg.enabled {
        tracing::info!("telemetry: disabled by config; metrics endpoint will not be contacted");
        return;
    }

    let endpoint = format!("{}/v1/telemetry", cfg.endpoint.trim_end_matches('/'));
    let interval = cfg.interval_secs.max(60);
    // Sample the live player count periodically so we can report a real peak.
    let sample = 60u64.min(interval);

    tracing::info!(
        endpoint = %endpoint,
        interval_secs = interval,
        "telemetry: enabled (anonymous, opt-out). Set [telemetry] enabled = false to disable."
    );

    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("kojacoord-proxy/", env!("CARGO_PKG_VERSION")))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "telemetry: failed to build HTTP client; disabling");
                return;
            },
        };

        // Small initial delay so startup isn't competing with the first ping.
        tokio::time::sleep(Duration::from_secs(30)).await;

        loop {
            // Track the peak online count across this interval.
            let mut peak = state.sessions.len();
            let deadline = Instant::now() + Duration::from_secs(interval);
            while Instant::now() < deadline {
                tokio::time::sleep(Duration::from_secs(sample)).await;
                peak = peak.max(state.sessions.len());
            }

            let payload = TelemetryPayload {
                instance_id: &state.config.proxy.server_id,
                version: env!("CARGO_PKG_VERSION"),
                os: std::env::consts::OS,
                arch: std::env::consts::ARCH,
                player_peak: peak.min(i32::MAX as usize) as i32,
                backend_count: state.config.servers.len().min(i32::MAX as usize) as i32,
            };

            match client.post(&endpoint).json(&payload).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!("telemetry: ping accepted ({})", resp.status());
                },
                Ok(resp) => {
                    tracing::debug!("telemetry: endpoint returned {}", resp.status());
                },
                Err(e) => {
                    // Never noisy: telemetry failures are entirely non-fatal.
                    tracing::debug!(error = %e, "telemetry: ping failed (ignored)");
                },
            }
        }
    });
}
