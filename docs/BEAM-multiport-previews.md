# Frontend and API previews

Beam can serve several fixed local loopback ports through one authenticated preview hostname. The frontend is the default destination. Optional path routes select a different approved local destination using the longest path prefix on a segment boundary.

```sh
tunnex beam publish --org ORGANIZATION_UUID --port 3000 --name "Checkout review" --duration 1h --reviewer-user REVIEWER_UUID --route /api=8080
```

`/api/orders` reaches `127.0.0.1:8080/api/orders`; `/apiary` reaches the frontend port. Paths and query strings are preserved. Configure the backend to serve its API prefix; Beam does not strip prefixes. Browser frontend calls should use the same-origin `/api` URL instead of an absolute localhost URL. Existing browser authorization, explicit reviewer grants, expiry and withdrawal cover every route.

CLI `--route` is repeatable, up to eight routes. It inherits the root numeric loopback address, HTTP/HTTPS protocol, and optional local CA. HTTPS verifies certificates for the selected numeric loopback identity; certificate verification is never disabled. Optional `--project UUID` associates the session with a saved project and requires the project's matching preset.

The desktop New share dialog includes optional API path and port fields when the server advertises support. Check app verifies every configured destination before publishing. Find local apps probes only six common HTTP ports (3000,3001,5173,8000,8080,4200) on numeric 127.0.0.1, only after an explicit click; it never scans a LAN or inspects process commands.

Compatibility is additive under Beam protocol 1. New servers advertise `path_routes_v1` and `saved_projects_v1` capabilities. A routed share cannot issue a connector to an older client that omits the route capability, preventing a legacy publisher from forwarding API paths to the wrong frontend port. New CLI/desktop clients refuse unsupported route servers before creating a share. The existing fixed-target digest and create idempotency digest include every route prefix and destination. Targets are immutable for a share; changing routes requires a new publication session.

Verification: Go real TLS-channel tests cover frontend/API dispatch, segment boundaries and authority-header removal. Native Electron transport fixtures cover routed API requests with queries, reviewer authentication, and active SSE/WebSocket closure on revoke/authority outage. Existing transport, CLI and desktop Beam tests remain required.
