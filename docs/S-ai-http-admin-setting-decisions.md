# Instance administrator control for AI over HTTP

Status: implemented in a labeled review build; explicit user clarification on 2026-10-01 supersedes
S-public-ip-https's decision to offer only private HTTP exceptions. Retain the
working HTTPS endpoint and IP certificate support.

## Decisions

- Locked: provide a persisted, instance-administrator-only UI setting permitting
  AI Gateway over HTTP, including public HTTP. Default off; concise warning
  explains that HTTP does not encrypt credentials or requests in transit.
- Locked: enforce authorization and policy on the server. Organization owners
  without instance administration cannot change the installation policy.
- Locked: HTTPS stays available; disabling the HTTP option reinstates the HTTP
  restriction. Do not weaken upstream TLS validation, authentication, encrypted
  credential storage or provider network policy.
- Locked: the setting must be reachable by the installation administrator on a
  supported HTTP console. Handle request scheme, cookies and trusted proxies
  consistently, without interpreting a VPN connection as private routing.
- Locked: preserve policy across restart and signed upgrades, and preserve the
  existing model/provider data, keys, certificates and original gateway.
- Locked: apply a backed-up review build on the existing AWS CP, verify the UI
  and API behavior over HTTP and HTTPS, then stop for user review. No release
  publishing or merge without explicit authorization.

## Acceptance

Default deny; admin opt-in allows HTTP; HTTPS still works; unauthorized users
cannot change policy; disabling restores HTTP restriction; policy persists over
restart/upgrade. Browser evidence must show the setting location and usable AI
controls. Container health alone is insufficient. Record exact deployment and
wire evidence during the work.

Evidence: [live HTTP/HTTPS walk](../walk-artifacts/ai-http-admin-20261001.md).
