# LS-UX-1 — Local Sharing: operator setup, full-feature audit, decisions

Branch `story/ls-ux-1` (from `origin/main` 43d021a9). Internal code name of the
feature is **Beam** (`apps/api/internal/beam`, `apps/app-proxy/cmd/beam-proxy`,
`tunnex beam …`, `deploy/beam/`). Customers only ever see **Local Sharing**.

Read end to end for this paper: installation serving (`beam/domain_settings.go`,
`beamreadiness/readiness.go`, `http/beam_readiness_handlers.go`), organization
policy (`beam/authority.go`, `beam/impact.go`), publish (`apps/cli/internal/cli/beam*.go`,
web `BeamCliPublisher`), reviewer serving (`app-proxy/cmd/beam-proxy`,
`app-proxy/internal/proxy/{beam,handler,unavailable}.go`), authority
(`http/beam_proxy_authority.go`), web pages (`pages/Beam.tsx`, `Settings.tsx`,
`WorkspaceFeatureControl.tsx`, `BeamPolicySettings.tsx`,
`BeamDomainReadinessSettings.tsx`), deployment (`deploy/beam/*`,
`deploy/upgrade.sh`, `deploy/app-access/*`, `.github/workflows/ci.yml`) and the
public docs page (`tunnex-web …/local-sharing.md`, read-only).

---

## A. What an operator must set up to qualify installation serving

### A.0 Blockers found — read first

These two make a *supported* Local Sharing installation impossible today. They are
not fixable as a small, safe change in this PR (see C.4) and are founder decisions.

| # | Blocker | Evidence |
|---|---------|----------|
| **B1** | **No signed Local Sharing proxy image is published.** Release CI builds and signs `api web nginx node-agent migrate operator ai-engine app-proxy` only; the release descriptor and `releaseverify` know nothing about `beam-proxy`. `deploy/beam/compose.yml` and `verify-config.py` require a *verified immutable digest*. The only way to run the proxy today is to build `deploy/docker/beam-proxy.Dockerfile` yourself, so it has no release signature. | `ci.yml` image matrix (~l.1197), `IMAGES=` (~l.1329), descriptor (~l.1621) |
| **B2** | **The one-command upgrade (`upgrade.sh`) does not manage Local Sharing.** Before this PR an installation with the Local Sharing overlay either (a) was refused with a misleading *App Access* message: Local Sharing only, the API mounts `app_restore` so it is counted as App Access → "App Access requires TUNNEX_APP_ACCESS_BASE_DOMAIN"; or with App Access → "composition must be tunnex.yml plus exactly one App Access overlay"; or (b) if the overlay had been recorded by `tunnex-app-access adopt`, the upgrade recreated the stack from the managed files only, **left the old `beam-proxy` running against the new API** (it stops only `app-proxy`) and never updated it. This PR changes (a)/(b) into one clear, early refusal naming Local Sharing, with the remove → upgrade → re-add steps (C.4). A real one-command upgrade needs a managed overlay plus a pinned signed image (B1). | `deploy/upgrade.sh` classifier, `admit_app_access`, l.1043–1063 |

Until B1 and B2 are done, a Local Sharing recording on the demo is a **manual,
self-built, not-upgrade-safe** setup. Say so off camera; do not present it as
the supported install path.

### A.1 Can Local Sharing reuse the App Access edge on the demo? **No.**

The demo has `app-proxy` owning public TCP 443, dispatching the exact console host
to Caddy on `127.0.0.1:8446`, and serving `*.cp.tunnex.app` with a wildcard
certificate.

- **Separate process.** Local Sharing is served by its own `beam-proxy`
  container (browser listener + publisher connector listener). `app-proxy`
  cannot serve shares, and has no SNI passthrough to forward them.
- **Separate public 443.** The readiness check always opens the wildcard check on
  port **443** of the address that `*.<sharing domain>` resolves to. `app-proxy`
  already binds 443 on the demo address, so the Local Sharing **browser**
  listener needs **a second public IPv4 address that the VM can bind**. A
  shared-IP TLS-passthrough edge is not qualified.
- **Separate domain and certificate.** The sharing domain must be either
  exactly the console host (`cp.tunnex.app`) or a *different registrable domain*.
  A sibling such as `share.tunnex.app` or `x.cp.tunnex.app` is refused (cookie/
  site isolation from the console). `cp.tunnex.app` is already App Access's base, so
  it is now refused as well (this PR, C.2). **The demo needs a separate registrable
  domain** (e.g. `tunnex-share.dev`) with its own wildcard certificate. The check
  requires the exact SAN `*.<sharing domain>`. `*.cp.tunnex.app` cannot be reused.
- **Connector can share the existing address.** The connector check dials the
  URL's own port and pins the TLS name `tunnex-beam-proxy` (installation CA), so
  `https://cp.tunnex.app:8447` works. This PR adds `TUNNEX_BEAM_CONNECTOR_PORT`
  so the connector no longer needs a second 443.
- **Shared, harmless:** the API's private authority listener `:8445` and the
  `app_restore` barrier volume (both are set by either overlay; the Local Sharing
  overlay sets them itself, so **Local Sharing does not need App Access** and
  vice versa). The beam authority path does not check the App Access licence.

### A.2 Ordered checklist (compose install shaped like the demo)

Server-side (operator, on the host):

1. **Image (B1).** Obtain a Local Sharing proxy image by digest. Today: build
   `deploy/docker/beam-proxy.Dockerfile` from the *same release tag* as the API
   and use the local `sha256` image ID. When B1 ships, use the signed digest
   that `releaseverify` prints.
2. **Domain.** Pick a sharing domain that is a different registrable domain
   from the console (not `*.tunnex.app`) and not the App Access base. Example:
   `tunnex-share.dev`.
3. **Second public IP** for the browser listener (GCP: reserve a static
   external IP and attach it so that the VM can bind it, e.g. protocol
   forwarding to a target instance, or a second NIC). Note its local bind
   address as `TUNNEX_BEAM_PUBLIC_BIND_IP`.
4. **DNS.** `*.tunnex-share.dev  A  <second IP>`. The connector reuses
   `cp.tunnex.app` (existing A record). Private, loopback and link-local
   answers fail the check.
5. **Firewall.** Inbound TCP 443 → second IP (everyone, reviewers' browsers).
   Inbound TCP 8447 → VM (publishers' computers). Never publish 8445 (authority)
   or 9093 (proxy admin).
6. **Public certificate.** A trusted wildcard certificate for
   `*.tunnex-share.dev` (DNS-01). Put `public-cert.pem` (full chain) and
   `public-key.pem` in the secrets dir. Readiness never outlives the
   certificate. The proxy reads it at start, so restart it after renewal.
7. **Proxy credential + connector certificate.** Both commands need the
   database, the master key and a **writable** restore-barrier lock. The serving
   API mounts the barrier read-only, so run them in a one-off API container
   from the installed release: `docker compose <your -f files> run --rm --no-deps
   --entrypoint backupctl api …`, with the `<project>_app_restore` volume mounted
   writable and a new, absolute, private output directory bind-mounted. This is
   the same vehicle UPG-1/AA-EN-1 use for `app-preflight` and App Access
   issuance.
   `backupctl app-proxy-issue --name local-sharing-proxy --output /out/authority.token`, then
   `backupctl beam-proxy-certificate --output-dir /out/connector`. The second
   gives `gateway-cert.pem`, `gateway-key.pem` (TLS name `tunnex-beam-proxy`)
   and `agent-ca.pem`. *The exact mount flags have not been walked on a
   live host in this story; dry-run them on a scratch host before recording.*
8. **Secrets directory** (e.g. `/opt/tunnex/beam-secrets`): `authority.token`,
   `agent-ca.pem`, `gateway-cert.pem`, `gateway-key.pem`, `public-cert.pem`,
   `public-key.pem`. Owner uid 10001, keys/token mode 0600 or 0400. Mounted read-only.
9. **`.env` additions:** `TUNNEX_BEAM_PROXY_IMAGE=<repo>@sha256:…`,
   `TUNNEX_BEAM_PROXY_SECRETS_DIR=/opt/tunnex/beam-secrets`,
   `TUNNEX_BEAM_PUBLIC_BIND_IP=<second IP local address>`,
   `TUNNEX_BEAM_CONNECTOR_BIND_IP=<VM address>`, `TUNNEX_BEAM_CONNECTOR_PORT=8447`,
   `TUNNEX_BEAM_BASE_DOMAIN=tunnex-share.dev`,
   `TUNNEX_BEAM_PROXY_URL=https://cp.tunnex.app:8447`. The last two only
   pre-fill the console form; they grant nothing.
   `TUNNEX_BEAM_DOMAIN_READY` is ignored for admission. Leave it `false`.
10. **Compose.** Add `-f beam.yml`. Release hosts do not receive it
    (`upgrade.sh` `HOST_FILE_LIST` has no Local Sharing files), so copy
    `deploy/beam/compose.yml` and `verify-config.py` from the **same source tag**
    as the installed release. and
    profile `beam` to the existing composition (`tunnex.yml` + `app-access.yml`).
    Render and check: `docker compose … --profile beam config --format json |
    python3 deploy/beam/verify-config.py`. Then `up -d` (recreates `api`, runs
    `beam-restore-init`, starts `beam-proxy`).

In the console:

11. **Server administrator → Settings → Local Sharing domain**: enter the sharing
    domain and connector URL, tick **Allow Local Sharing on this installation**,
    **Review serving changes → Save**, then **Check DNS and TLS**. All five
    checks must pass: configuration, wildcard DNS, serving HTTPS certificate,
    unallocated-hostname denial, connector TLS. The server re-checks every minute;
    each result is valid ≤ 5 minutes.
12. **Org owner/admin → Settings → Local Sharing**: choose publisher groups (or
    **Open for all users**), the reviewer audience, lifetime and share limit, then
    **Review policy changes → Confirm**.
13. **Settings → Features → Local Sharing**: turn on, confirm.
14. **Publisher**: install the `tunnex` CLI (or desktop client), then in **Local
    Sharing → My shares → Share a local app** generate and run the command.

Upgrade (today, with this PR): `upgrade.sh` refuses up front with a Local
Sharing message (B2). Steps: recreate the stack without `beam.yml` (this stops
the proxy and ends live shares), run the upgrade, then rebuild/re-add the proxy
from the new release and re-run step 11's check. A managed, one-command path is
founder decision D2.

---

## B. Audit (one row per issue)

Roles: **SA** server administrator (installation), **OA** org owner/admin (`beam:policy_manage`),
**P** publisher, **R** invited reviewer, **X** not invited / expired / revoked.

| # | Page / surface | Role | Problem | Disposition |
|---|----------------|------|---------|-------------|
| 1 | Settings → Features → Local Sharing | OA | "Installation serving setup must be qualified before enabling publishing." is jargon and says neither who nor how. The only link, "Review sharing policy", leads to the org policy page, which cannot fix it. Dead end. | **Fixed.** One neutral sentence covers both "never set up" and "set up but a check is now failing" (the API cannot tell them apart): "isn't available on this server right now: its setup is incomplete or a server check is failing". SA gets "Open Local Sharing domain setup". Others get "Ask a server administrator to check Local Sharing setup". Policy link kept, renamed "Open sharing policy". The same wording is used on the policy page, the workspace notice, diagnostics, the CLI and the API refusal. |
| 2 | Org policy save (API `impact.go`) + Settings → Local Sharing | OA | While the feature is on, any lapse in serving checks (≤5 min, background refresh) refused **every** policy save. That included *tightening* (removing reviewers, shortening lifetime). The UI disabled "Review policy changes" the same way. Security-adverse dead end. | **Fixed.** Refuse only when turning the policy on while setup is not current. Edits to an enabled policy and turning it off always work. Serving still denies every share while checks are not current. |
| 3 | Settings → Local Sharing → "Operator setup guide" | OA | Wrong and incomplete. It presents `TUNNEX_BEAM_*` env vars as the setup (they only pre-fill), and omits the proxy service, second IP, certificates, credential and firewall. | **Fixed.** Short role-correct summary that points to the server admin page and the runbook. |
| 4 | Local Sharing domain page | SA | Jargon ("Authority at last read", "operator", "independent checks", "Setup needs repair"). A failed check gives no next step. No overview of what must exist before checking. | **Fixed.** Plain statuses, a "Before you check" list, a fix hint for each failing check, "Serving is turned on/off for this installation". |
| 5 | Local Sharing workspace notice | all | Policy off **and** setup incomplete showed "Local sharing is off → Open feature settings", but the switch there is blocked → loop. "Installation operator" differs from the rest of the product's "server administrator". | **Fixed.** Setup-incomplete is shown first, with an SA link or "ask a server administrator". Wording aligned. |
| 6 | Reviewer refusal page (proxy) | R/X | Says "TUNNEX BEAM" and "Reopen the original Beam link" (code name). No way back to the console. | **Fixed.** Says "Local Sharing" with actionable copy (ended, paused or no access → open **Shared with me** or ask the person who shared it). Adds a fixed "Open Local Sharing" console link, identical for every refusal. Upload-limit text no longer says "Beam". |
| 7 | CLI `tunnex beam publish` precheck | P | One message for three causes ("unavailable under current organization policy or serving-domain readiness"). | **Fixed.** Three messages: server setup incomplete → ask SA; feature off → ask org admin; not a publisher → ask org admin to add you. |
| 8 | CLI HTTP errors | P | 403/400 messages vague. | **Fixed** (403 names the next step). 400 kept: the server message is not passed through, so a specific cause cannot be named safely. |
| 9 | Installation domain save (API) | SA | Sharing domain could equal or nest inside the App Access base (e.g. both `cp.tunnex.app`). Readiness could then pass against **App Access's** edge (its wildcard cert + 404 for unknown hosts) while shares were unreachable. Misleading, and the two features would share a hostname space. | **Fixed, both directions.** A Local Sharing save is refused against the saved App Access base (environment fallback). An App Access domain save is refused against the saved Local Sharing domain. Both messages are clear. |
| 10 | `deploy/beam/compose.yml` | SA | Connector hard-wired to a second **443**, so two extra IPs were needed on a host that already serves 443. | **Fixed.** `TUNNEX_BEAM_CONNECTOR_PORT` (default 443). The verifier accepts the same IP when the ports differ. |
| 11 | `upgrade.sh` | SA | B2 above: misleading App Access refusal, or an old proxy left talking to a new API. | **Partly fixed.** Clear early refusal naming Local Sharing, before any backup or mutation, with steps. Managed upgrade **deferred** (D2). |
| 12 | Release images | SA | B1 above. | **Deferred** (D1): CI matrix, signing, descriptor and `releaseverify` change. Not a small, safe edit. |
| 13 | Proxy authority credential | — | `/internal/beam/*` accepts any App Access proxy credential, and the beam credential is accepted by App Access authority. They are one table with no purpose binding. A compromised App Access proxy could call Local Sharing authority (and vice versa). Both are operator-run on the same host. | **Deferred** (needs a schema column, a `backupctl --purpose` flag and a rollout for existing credentials). Recorded in C.3 / D3. |
| 14 | `deploy/beam/README.md` | SA | Missing: App Access coexistence, the domain rule, the connector port, upgrade steps. | **Fixed.** Sections added. |
| 15 | Public docs page (tunnex-web, read-only) | all | Calls the server page "Local Sharing setup". The console calls it "Local Sharing domain". It also omits blockers B1/B2. | **Deferred** (read-only repo). The console label stays; the docs owner should rename it to "Local Sharing domain". |
| 16 | Unknown / expired / revoked / not-invited reviewer | X | One identical refusal page for every cause. | **Kept by design** (C.1). Only the wording was fixed (#6). |
| 17 | Publish button with publishing unavailable | P | The button is disabled without saying why. | Already covered: the workspace notice above it states the reason (improved in #5). |
| 18 | Desktop client publish flow | P | Lives in the read-only `tunnex-desktop` repo (`apps/client/src/main/beam*.ts`). | **Not audited for edits** (read-only). The flow exists, so "CLI or desktop client" in the console copy is true. |
| 19 | Local Sharing → Events, share diagnostics | OA/P | The events table and its filters showed raw codes (`beam.share.created`, `denied`, `grant_removed`). Diagnostics showed raw `state`/`connectivity` values (`origin_unavailable`). Copy said "installation operator" and "desktop client" only. | **Fixed.** Readable labels for actions, outcomes, reasons, states and connectivity, with readable fallbacks for unknown codes. Wording aligned. Access Events details use the action label. |
| 20 | Dashboard upgrade (Upgrade center) | SA | The new refusal exited before writing status, so a dashboard upgrade would sit at "verifying". The failed banner prints raw reason codes. | **Fixed for this case.** Status `failed` / `local_sharing_unmanaged`, shown as a plain sentence. Raw codes for other upgrade failures, and the same missing-status gap for existing App Access admission refusals, are pre-existing. **Deferred** to an upgrade-UX story. |
| 21 | Share detail, feedback, rooms, pause/stop/extend, reviewer launch page (`BeamLaunch`), Access Events "Local Sharing access" list | OA/P/R | Skimmed, not audited line by line. The launch page's invalid-link, wrong-organization and expired states are worded and actionable. The Access Events list humanizes reasons. The generic Audit Log page shows raw action names for **every** feature, by platform convention. | No change in this PR. A line-by-line pass of these surfaces and the desktop client is a follow-up. |

---

## C. Decisions and security analysis

**C.1 One refusal page for every reviewer failure.** Not invited, expired, paused,
revoked and unknown hostnames all get the same 403 page. A hostname is only a
locator, so telling these apart would let anyone probe which links exist or who
was invited. The page now names the product, lists the common causes as
possibilities rather than a diagnosis, and gives one fixed console link. The link
is identical for every refusal, so it reveals nothing.

**C.2 Domain separation.** The sharing domain stays in its own site, with no
change to the existing rule (console host or independent registrable domain). It
is now also kept apart from App Access. Separate hostname spaces mean neither
proxy's readiness can be satisfied by the other's edge, and host-scoped cookies
never meet. The check only runs when an App Access base exists, so Local Sharing
still works without App Access.

**C.3 Security posture — what this PR does not change.** Every gate stays
server-side: measured DNS/TLS readiness (≤5 min, capped by certificate expiry), the
restore barrier, versioned settings with an atomic end-shares confirmation, org
policy, per-share grants, browser sign-in with optional fresh MFA, and leases of
≤5 s. Item #2 loosens only *who may save a policy while checks lapse*. That cannot
add serving: admission and lease renewal still require current readiness, and
turning the policy **on** still requires it. Item #6 adds a static console link,
not a redirect. Item #10 keeps TLS 1.3 + mTLS on the connector; only the
published port number changes. Open risk: #13 (shared proxy credential table),
deferred.

**C.4 Why upgrade.sh refuses instead of carrying Local Sharing.** Carrying it
needs a signed image to pin (B1), a hashed managed overlay, classifier and port
admission, and stop-before-migrate ordering for `beam-proxy`. That mirrors the
App Access UPG work (several hundred lines of shell plus contract tests). Doing
it without a signed image would mean pinning an unsigned digest, which weakens
security. A clear refusal before mutation is honest and safe. The previous
behaviour could leave an old proxy talking to a migrated API.

**C.5 Founder decisions needed.**
- **D1** Publish and sign `tunnex-beam-proxy` in release CI (matrix, descriptor,
  `releaseverify -require-beam-proxy`).
- **D2** Make `upgrade.sh` manage `beam.yml` like `app-access.yml` (after D1).
- **D3** Purpose-bind proxy credentials (App Access vs Local Sharing).
- **D4** For the demo video: a second public IP on the demo VM and a separate
  registrable sharing domain (A.1), or wait for D1/D2 and record later.
