# Kojacoord Roadmap

This file is the single source of truth for the public roadmap shown on
[kojacoord.net](https://kojacoord.net). The landing page reads it directly from
the default branch, so editing it here updates the site.

**Format:** each `##` heading is a phase. Each list item is a roadmap entry —
use `- [x]` for shipped, `- [ ]` for not-yet-done. Optionally add `— short note`
after the text for extra context.

## Shipped
- [x] Protocol support: 1.6.x (PreNetty)
- [x] Protocol support: 1.13.x
- [x] Protocol support: 1.14.x
- [x] Protocol support: 1.15.x
- [x] Protocol support: 1.16.x
- [x] Protocol support: 1.17.x
- [x] Protocol support: 1.18.x
- [x] Multi-version protocol support — Java Edition 1.7.x through 1.21.x with automatic conversion
- [x] Authentication pipeline — online-mode Mojang session auth + offline-mode support
- [x] Anti-cheat engine at the proxy edge

## In Progress
- [ ] Protocol support: 1.19.x
- [ ] Protocol support: 1.20.x
- [ ] Protocol support: 1.21.x
- [ ] Protocol support: 26.x (Latest - 26b23)

## Planned
- [ ] Bedrock edition bridging
- [ ] Plugin marketplace / registry
- [ ] Mojang Realms compatibility layer

## Exploring
- [ ] QUIC / HTTP/3 client transport — once a vanilla client supports it