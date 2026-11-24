# AA-EN-1 Phase 1a: implementation notes

Status: local branch `story/aa-en-1-phase-1a`. Not pushed, not released, not run
on a live host. Implements Phase 1a of
[AA-EN-1](AA-EN-1-first-class-app-access-enablement.md) under the founder rulings
E1–E12 and the item added to Phase 1a by founder ruling (dashboard forward fix).

## What was built

1. **Proxy endpoint over the agent channel (E5).**
   - API: `GET /agent/app-access/proxy-endpoint` on the mTLS agent channel returns
     `{"enabled":true,"port":8444,"host":"<optional>"}` or `{"enabled":false}`.
     Enabled only when the installation publishes the gateway listener
     (`TUNNEX_APP_PROXY_GATEWAY_PORT`, set by the managed overlay),
     `TUNNEX_APP_ACCESS_LOCKED` is not `true`, App Access is entitled, and the
     gateway's organization has the feature on. Gateway identity required (403
     otherwise); an unreadable organization setting is 503, never "off". An invalid
     `TUNNEX_APP_PROXY_GATEWAY_PORT`/`_HOST` disables delivery and is logged; it
     never stops the API.
   - Gateway: `TUNNEX_APP_PROXY_URL` is tri-state (URL overrides as before, `off`
     locks, unset follows). A supervisor polls every 5 s and starts, restarts (on a
     changed endpoint) or stops the browser pool without a restart. Errors and an
     older control plane's 404 keep the current state. Delivered hosts are also
     refused as app origins by the origin-check runtime (G2).
   - **G1 verified, `--add-host` is not needed.** `NewBrowserPool` always sets
     `ServerName = "tunnex-app-proxy"` and dials `target.Host`
     (`apps/node/internal/appaccess/browser.go`), and the TLS config trusts the
     enrollment CA through the rotating agent identity. A new real-TLS test dials
     `https://127.0.0.1:<port>` exactly as the supervisor does: the handshake
     succeeds against a `tunnex-app-proxy` leaf from the enrollment CA and fails for
     any other name or CA. The demo's host mapping was a naming convention only.
2. **Managed overlay and admission (E6).** The overlay publishes
   `${TUNNEX_APP_PROXY_GATEWAY_BIND_IP:-0.0.0.0}:${TUNNEX_APP_PROXY_GATEWAY_PORT:-8444}:8444`
   and passes the endpoint settings to the API. `tunnex.yml` publishes Caddy HTTPS
   as `${TUNNEX_EDGE_HTTPS_PUBLISH:-443}:443`; `docker compose config` renders it
   byte-identically to before with the default. UPG-1 admission accepts exactly the
   public listener alone (earlier overlays) or the public plus gateway listener,
   each from `.env`, and the composition recorded by `adopt`.
3. **`tunnex-app-access adopt`** (`deploy/app-access/tunnex-app-access.py`, stdlib
   only, shipped in the API image's host files and installed next to `upgrade.sh`).
   Files-only conversion: it never stops or recreates a container; the next upgrade
   recreates the stack from the managed files and admission accepts the recorded
   composition only while the hand-written overlays are unchanged (hashes). See the
   App Access README for the procedure and rollback.
4. **`tunnex-app-access renew`** (stop-gap until Phase 1b). Validation through an
   in-memory TLS handshake with the Python standard library: chain to the system or
   given trust, wildcard coverage (random label) and portal coverage when the proxy
   forwards the console, validity window, key match, at least 7 days left, later
   expiry than installed. Atomic 0400 install keeping the owner, `*.previous` kept,
   proxy-only restart with readiness wait, automatic restore of the previous pair if
   the proxy does not become ready.
5. **Dashboard forward fix.** The refusal, verified by reading the code at the UPG-2
   base (9807d33c): `release.Compare` sets `Reason = "no newer release is available"`
   with `Available=false` whenever `next.Sequence <= current.Sequence`
   (`apps/api/internal/release/manifest.go:275-276`), and `RequestHostUpgrade` then
   answers 409 `upgrade_not_available`
   (`apps/api/internal/http/host_upgrade_handlers.go:43`). Now `release.Status`
   carries `Rerunnable` (same sequence and source SHA), `GET /admin/upgrade` reports
   `rerun_available` after a failed upgrade to that same source (not after
   `app_access_authority_changed`), and `POST /admin/upgrade/rerun` (no body; the server pins the target) requests
   that pinned target. Same authorization (deployment administrator) and the same
   audit action with `rerun: true` in its metadata. The host side already accepted a
   same-sequence, same-source re-run (UPG-2 U4), so the runner is unchanged.
   The step-up question is listed under decisions below.

## Demo procedure (operator, after the release ships)

1. Upgrade nothing yet. Extract the host files from the verified release's API image
   and run `adopt` (dry run, then `--apply`), as in the App Access README.
   Expected plan on the demo: public `0.0.0.0:443`, gateway `10.70.0.2:8444`,
   console forwarded to `https://caddy:443` with server name `cp.tunnex.app`,
   `TUNNEX_EDGE_HTTPS_PUBLISH=127.0.0.1:8446`,
   `TUNNEX_APP_PROXY_GATEWAY_HOST=10.70.0.2`.
2. Replace both `upgrade.sh` copies once (UPG-1 D3, the demo is on v0.1.45 or
   older), then run the upgrade from the command line.
3. Recreate each VM gateway without `TUNNEX_APP_PROXY_URL` and without
   `--add-host tunnex-app-proxy:10.70.0.2`, on the new agent image. It follows the
   control plane within about 5 seconds.
4. Before 2027-02-22: renew with certbot DNS-01 and `tunnex-app-access renew`.

## Release notes text

**App Access: gateways find the proxy by themselves.** The control plane now tells
gateways where the App Access proxy listens, over their existing secure channel. On
a gateway, `TUNNEX_APP_PROXY_URL` now means: unset follows the control plane (the
browser connector starts and stops without a restart), a URL keeps forcing that
address as before, and `off` keeps App Access off on that gateway. No
`/etc/hosts` or `--add-host` entry is needed. Upgrade the control plane before
gateways.

- **Docker Compose with App Access:** the proxy now also publishes its gateway
  listener on port 8444 on all addresses (mutual TLS with your enrollment CA, like
  the agent port 8443). To narrow it, set `TUNNEX_APP_PROXY_GATEWAY_BIND_IP` in
  `.env`; to change the port, `TUNNEX_APP_PROXY_GATEWAY_PORT`; if gateways reach
  the control plane at another address, `TUNNEX_APP_PROXY_GATEWAY_HOST`. Open TCP
  8444 from your gateways in your cloud firewall. Set `TUNNEX_APP_ACCESS_LOCKED=true`
  to stop delivering the endpoint to gateways.
- **Helm gateways:** a gateway with `appAccess.enabled: false` no longer sets
  `TUNNEX_APP_PROXY_URL`, so it now follows the control plane. It still runs the
  browser connector only when App Access is set up on the control plane and turned
  on for its organization.
- **Hand-written App Access layouts** (more than one overlay file) must be adopted
  once with `tunnex-app-access adopt` before they can be upgraded. See the App
  Access README.
- **Certificate renewal:** `tunnex-app-access renew` validates a renewed public
  certificate and installs it with a controlled proxy restart.
- **Failed upgrades:** server administrators can run the same release again from
  the dashboard after a failed upgrade. Older releases are never installed.
- Installations without App Access are unchanged.

## Verification (local, this branch)

- Go: `apps/api/internal/http` endpoint validation, enabled truth table, handler over
  a throwaway PostgreSQL (gateway required, unknown certificate, no-store, 503 on
  unreadable organization); `apps/api/internal/release` re-runnable rule;
  host-upgrade handler re-run tests; `apps/node/internal/appaccess` tri-state,
  endpoint URL, supervisor start/keep/restart/stop with errors and 404, real-TLS G1
  test; `apps/node/internal/control` endpoint client (404 mapping) over mTLS.
- Deploy contracts under `sh` and `dash`: managed port set admitted, narrowed port
  admitted, drift and extra ports refused, demo layout refused until adopted,
  adopted layout admitted and recreated from managed files only, record removed,
  edited overlay or changed file list refused; tool installed by the upgrade.
- Python: adopt against the real `docker compose config` with a faked container
  inspection (dry run, apply, idempotence, managed render equals the running proxy,
  admission predicate from `upgrade.sh`, unknown drift, console reachability,
  identity drift, unpublished gateway listener); renew with openssl-made
  certificates (expired and not-yet-valid cases need OpenSSL 3.4 or newer).
- Web: Upgrade Center re-run offered only when the server offers it, confirmation,
  request body.
- `make generate` (OpenAPI change) regenerated Go, CLI and TypeScript types.

## Not verified here (needs a Linux host / the demo)

- A real gateway agent dialling a real proxy by IP across a network (the TLS test is
  loopback with test certificates).
- `docker restart` of a real proxy and its readiness after `renew`, file ownership
  uid 10001 as root, certbot output with Let's Encrypt's real chain against the
  system trust store.
- `adopt` against the live demo (container inspection of the real containers, the
  real `app-access-demo.yml`, whether the demo's Compose version renders it the same).
- The full upgrade of the adopted demo layout (UPG-1's own unverified items still
  apply), and the dashboard runner re-run end to end.

## Decisions for the founder

- **Step-up for the dashboard re-run.** The ruling says "the same step-up and audit
  as other host actions". The only existing host action, the dashboard upgrade,
  has no re-authentication step (deployment administrator, CSRF, audit). The re-run
  matches it exactly. Recommendation: keep them identical now, and add SA-UI-1-style
  re-authentication to both upgrade and re-run together in one follow-up, so the two
  never differ.
- **Console reachability during an upgrade on adopted (S2) hosts.** With
  terminate-and-forward the console goes through the proxy, which the upgrade stops
  while the API migrates and leaves stopped after a failure (UPG-1 invariant 5). On
  the demo, a failed upgrade therefore makes the console unreachable on public 443
  and the dashboard re-run unusable there; the operator re-runs from the command line.
  Recommendation: accept for adopted installs (documented); S1 passthrough in Phase 2
  removes it for new installs.
- **Gateway listener renewal** (365-day leaf) is not part of this `renew`; the demo
  leaf expires around 2027-11. Recommendation: add `renew --gateway` through the
  one-off `backupctl app-proxy-certificate` helper in Phase 1b.
- **Reachability report** (`proxy_reachable | tls_failed | unreachable`) is not
  built; the supervisor logs start, stop and refusals only. Recommendation: ship it
  with the Phase 1b readiness panel, which is its only consumer.
