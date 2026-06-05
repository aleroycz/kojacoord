# Kojacoord Roadmap

This file is the single source of truth for the public roadmap shown on
[kojacoord.net](https://kojacoord.net). The landing page reads it directly from
the default branch, so editing it here updates the site.

**Format:** each `##` heading is a phase. Each list item is a roadmap entry —
use `- [x]` for shipped, `- [ ]` for not-yet-done. Optionally add `— short note`
after the text for extra context.

## Shipped
- [x] Multi-version protocol support (1.8 → latest)
- [x] Authentication pipeline (online + offline) — Mojang session auth
- [x] Anti-cheat engine at the proxy edge
- [x] Native plugin system + `cargo-kpl` plugin builder
- [x] crates.io publishing with docs.rs documentation
- [x] Signed, multi-platform releases — cosign + SHA256SUMS
- [x] Anonymous, opt-out telemetry

## In Progress
- [ ] Cross-platform `.kpl` packaging — bundle Windows/Linux/macOS plugin libs
- [ ] Plugin signing tied to the integrity allowlist
- [ ] Unified plugin API surface across crates
- [ ] Public global metrics dashboard

## Planned
- [ ] WASM plugin runtime — sandboxed, portable plugins
- [ ] Hot-reload of plugins without restart
- [ ] Web management dashboard UI
- [ ] Cluster mode with autoscaling
- [ ] Per-player and per-region routing rules

## Exploring
- [ ] gRPC control plane for external orchestration
- [ ] Bedrock edition bridging
- [ ] Plugin marketplace / registry
