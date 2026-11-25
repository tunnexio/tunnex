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

> **Status after the founder ruling (section D):** B1 and B2 are **resolved in
> this branch** (signed image, managed upgrade). They take effect from the first
> release cut from it. The final checklist is **A.3**; A.2 is kept as the audit
> record of the pre-ruling state.

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
   `backupctl app-proxy-issue --purpose local-sharing --name local-sharing-proxy --output /out/authority.token`, then
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
| 11 | `upgrade.sh` | SA | B2 above: misleading App Access refusal, or an old proxy left talking to a new API. | **Fixed (D.2).** Managed profile with one-command upgrade. A hand-written setup is refused with adopt steps, and each refusal has a readable dashboard reason. |
| 12 | Release images | SA | B1 above. | **Fixed (D.1).** Signed `tunnex-beam-proxy` in CI and the descriptor, `-require-beam-proxy`, Helm `localSharing` by digest. |
| 22 | Single public IP | SA | The browser listener needs its own public IPv4 because 443 belongs to Caddy or App Access. | **Designed, deferred to LS-EDGE-1** (D.3): shared SNI-passthrough edge with PROXY v2. Deferred because it needs PROXY acceptance in Caddy and `app-proxy` to keep client addresses (security). |
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

---

## D. Founder ruling 2026-11-25 and the architecture it asks for

The ruling: "go with the best architecture; if code changes are needed, make them.
I want an easy, good user experience without confusion and extra work." This
section records the decisions for B1, B2, single-IP serving and the operator
checklist. It supersedes A.0/C.4/C.5 where they differ.

### D.1 B1: a signed Local Sharing proxy image (decided, built here)

`tunnex-beam-proxy` is published exactly like `tunnex-app-proxy`:
- the CI image matrix builds `deploy/docker/beam-proxy.Dockerfile` for amd64 and
  arm64 with the same provenance/SBOM/attestation steps;
- it is in the public-package gate and the burned-tag guard;
- the signed release descriptor gets `images["beam-proxy"]`;
- `release.Verify` requires both digests whenever the entry is present, which
  keeps older descriptors valid;
- `releaseverify -require-beam-proxy -print-env` prints
  `TUNNEX_BEAM_PROXY_IMAGE=ghcr.io/tunnexio/tunnex-beam-proxy@sha256:…`.

The compose overlay and the Helm chart only accept a digest. A self-built image
is no longer part of the supported path.

**One-time founder action:** the publish job also runs on `main` pushes
(`tunnex-build-<sha>`). So the **first main build after this merges** creates
the new GHCR package `tunnex-beam-proxy` as private, and its public-package
gate fails. Set the package to Public (org packages page), then re-run that
job. Later builds and releases pass.

### D.2 B2: Local Sharing is a managed upgrade profile (decided, built here)

It mirrors the App Access managed layout:
- The release ships the overlay as a host file (`local-sharing/compose.yml`
  in the API image, extracted by the hand-off). The installation keeps it as
  `<install>/local-sharing.yml`, hash-bound in `.env`
  (`TUNNEX_LOCAL_SHARING_COMPOSE_SHA256`). The profile is `beam`.
- **Admission, before any backup or change:**
  - the running `beam-proxy` must come from `tunnex.yml`, optionally
    `app-access.yml`, then `local-sharing.yml`, in that order;
  - its secrets directory and port bindings must equal `.env`;
  - the overlay hash must match;
  - the target release must carry a signed `beam-proxy` digest (verified with
    `-require-beam-proxy`).

  An unmanaged hand-written layout is refused with the exact adopt steps
  (copy the release's overlay, record its hash, recreate).
- **Apply:**
  - pin the signed digest in `.env`;
  - stop `beam-proxy` **before** the API migrates, so an old proxy never talks
    to a new API;
  - migrate and health-check the API;
  - start the new `beam-proxy` and wait for its health check (`/livez`:
    process and listeners up). Readiness (`/readyz`) depends on the
    installation's DNS/TLS checks, so it must not fail an upgrade.
  - Shares end on the restart (connectors drop). Their database state, policy,
    settings, events and the restore volume are kept.
- **Rollback:** the same forward-fix rule as the rest of the product. Re-run the
  upgrade, or restore the verified pre-upgrade backup with the documented
  restore procedure. A failed apply leaves `beam-proxy` stopped, so nothing
  serves from an unverified stack.
- **Independence:**
  - Local Sharing-only installs are recognised as such. The restore-volume
    mount from the Local Sharing overlay no longer makes the classifier think
    App Access is present.
  - App Access-only installs are unchanged.
  - Both together compose as `tunnex.yml, app-access.yml, local-sharing.yml`.

### D.3 Single public IP (evaluated; decided design, **not built in this PR**)

Options for serving `*.<sharing domain>` on the one public 443 that already
belongs to Caddy (base install) or `app-proxy` (App Access installs, the demo):

| Option | Verdict |
|---|---|
| E1. **SNI passthrough edge**: whichever process owns public 443 reads only the ClientHello SNI. It splices `*.<sharing domain>` raw TCP to `beam-proxy:8443` (TLS still terminates in `beam-proxy`). Every other SNI goes to the next owner, with a PROXY v2 header so client addresses survive. This is the same mechanism as App Access's accepted-but-unbuilt AA-EN-1 **S1**. | **Chosen design.** One IP, one edge. Share TLS and cookies never decrypt outside `beam-proxy`. Console TLS and ACME stay in Caddy. |
| E2. `app-proxy` terminates share TLS and forwards | Rejected: share plaintext in the wrong component, and it ties Local Sharing to App Access. |
| E3. Caddy layer-4 routing | Rejected (AA-EN-1 S3): custom Caddy build in the supply chain. |
| E4. Share URLs on a non-443 port | Rejected: confusing reviewer URLs, blocked by many corporate networks. |
| E5. Second public IP | Works today. Stays the supported layout until E1 ships. |

**Why E1 is not built here.** It cannot be done safely as a side change of a UX
story:
1. **Client addresses.** Spliced console and App Access traffic would reach
   Caddy and `app-proxy` from the edge's container address. The API's per-IP
   login throttling, rate limits and audit addresses would collapse to one
   value. That weakens security. Preserving them needs PROXY v2 *acceptance*,
   with an exact allow-list, in Caddy (built-in `proxy_protocol` listener
   wrapper, changes the base `tunnex.yml` edge) and in `app-proxy`.
2. **Ownership of 443 moves.** Moving 443 is an `.env` and port-admission
   change for `upgrade.sh`'s Caddy and App Access checks. App Access's adopted
   terminate-and-forward layout (the demo) needs its own migration.
3. **The same edge is App Access's S1.** Building it once in a shared
   `packages/apptransport/sniedge` (bounded ClientHello parse, peek timeout,
   connection cap, PROXY v2 writer), owned by "whoever holds 443", serves both
   features and keeps them independent. Building a Local Sharing-only copy now
   would be thrown away.

**Remaining work, as its own story (LS-EDGE-1, shared with AA-EN-1 S1):** the
`sniedge` package and its fuzz tests; PROXY v2 accept in `app-proxy` and in
Caddy; 443 ownership in `tunnex.yml`/the overlays (`TUNNEX_EDGE_HTTPS_PUBLISH`
already exists); `upgrade.sh` port admission; and a readiness check that accepts
"wildcard served via the shared edge". The readiness check needs no change in
substance: it already probes the real public 443 and the real certificate,
whatever forwards it.

**Separate registrable sharing domain: still required.** It is a real isolation
property, not a routing convenience:
- A sibling of the console (same eTLD+1) is *same-site*. Browsers send
  `SameSite=Lax/Strict` console cookies on requests that start from a shared
  app, and a share's JavaScript could set domain cookies that the console
  reads.
- Shared apps are arbitrary code from members' laptops, so they must be
  cross-site to the console.
- The console host itself is allowed only because no app lives on it.

### D.4 Operator checklist (in the docs and in the app)

The checklist lives in section A and, shortened, in the console's Local
Sharing domain page. Each failing check shows what is missing and the next
step.

### D.5 Security analysis of D.1–D.2

- **Supply chain:** only a signed, digest-pinned image runs, verified by the
  installed key through the same `releaseverify` path as every other image.
  Mutable tags are refused by `verify-config.py` and by the upgrade's
  digest pattern.
- **Upgrade ordering:** the old proxy is stopped before migration. The new one
  starts only after the API is healthy, and the proxy itself refuses to start
  while a restore marker is present (unchanged).
- **No new secrets path:** secrets stay in the operator's private directory.
  The upgrade only compares its path with `.env`; it never reads it.
- **Independence:** no code path requires App Access for Local Sharing, or
  the reverse. The shared authority listener and restore volume are set
  identically by either overlay.

---

## A.3 Final operator checklist (from the first release cut from this branch)

For a compose install. Shown in short in the console (Settings → Local Sharing
domain → Setup checklist). The commands are in `deploy/beam/README.md`,
"Install (managed layout)".

1. **Domain:** pick a registrable domain of its own, e.g. `tunnex-share.dev`
   (not `*.tunnex.app`, not the App Access base).
2. **Address:** a public IPv4 that the VM can bind and that Caddy/App Access
   don't use (until LS-EDGE-1). On GCP: reserve a static IP and attach it to
   the VM (alias/secondary NIC or protocol forwarding).
3. **DNS:** `*.tunnex-share.dev A <that IP>`. The connector reuses the console
   name: `https://cp.tunnex.app:8447`.
4. **Firewall:** TCP 443 → that IP from everyone; TCP 8447 → the VM from
   publishers. Never 8445/9093.
5. **Certificate:** a trusted wildcard `*.tunnex-share.dev` (DNS-01).
6. **On the host** (README steps 1–6):
   - copy the managed overlay from the API image and record its hash;
   - pin the signed proxy digest with `releaseverify -require-beam-proxy`;
   - issue `authority.token` and the connector certificate with a one-off
     `backupctl`;
   - install your wildcard certificate files;
   - add the six `TUNNEX_BEAM_*` settings and the `beam` profile to `.env`;
   - `docker compose -f tunnex.yml -f app-access.yml -f local-sharing.yml up -d`.
7. **Console, server admin:** Settings → Local Sharing domain. Enter the domain
   and connector URL, allow, save, then **Check DNS and TLS**. All 5 checks
   must pass.
8. **Console, org admin:**
   - Settings → Local Sharing: publishers and reviewers, then confirm;
   - Settings → Features → Local Sharing: turn on.
9. **Publisher:** Local Sharing → My shares → Share a local app → run the
   command.

**What the demo upgrade looks like afterwards:** the same single
`upgrade.sh --apply` (or the dashboard button). In order, it:
1. verifies the release, including the signed `beam-proxy` and `app-proxy`
   digests;
2. checks the App Access and Local Sharing layouts against `.env`;
3. backs up;
4. stops `app-proxy` and `beam-proxy`;
5. migrates the API;
6. verifies App Access authority;
7. starts `app-proxy`;
8. health-checks the API;
9. starts `beam-proxy` and waits for its liveness check.

Live shares end at the restart, so publishers re-run their command. Nothing
else changes. Any drift refuses before step 3 with a named setting.

**Precondition for the demo (founder decision / on-host check):** Local
Sharing expects App Access in the **managed** layout (`tunnex.yml` +
`app-access.yml`). Per AA-EN-1 E12 and the demo notes, the demo's adopted App
Access layout has **not yet been verified as one-click upgradable**. Verify
that on the host, or run the reviewed App Access adoption/upgrade, **before**
adding Local Sharing. Otherwise the upgrade refuses, without changing anything,
and names the App Access cause.

**Rollback:** forward fix by default (re-run). Restoring a backup follows the
App Access restore runner when App Access is installed. A Local Sharing-only
restore is documented in the runbook but has no automated fenced runner yet
(deferred).

---

## E. Founder ruling 2026-11-25 (second): single-IP edge, one-step enable, purpose-bound credentials

The founder approved building D.3 (LS-EDGE-1), a host command, and credential
purpose binding in this branch. The decisions are below. They supersede the
D.3 deferral and table row 13.

### E.1 Single public 443: SNI passthrough in the Local Sharing proxy

**Who owns 443:**
- **Neither feature, or App Access only:** unchanged. Caddy owns 443, or
  `app-proxy` does on the adopted/terminate-and-forward layout.
- **Local Sharing in shared-edge mode** (the default from the host command):
  `beam-proxy` owns public 443. Its browser listener peeks only at the TLS
  ClientHello. The peek is bounded to 16 KiB and 5 s, and a connection cap
  applies.
  - SNI exactly one label under the sharing domain: `beam-proxy` terminates
    TLS itself, as before.
  - SNI under the App Access base, when App Access is installed: raw TCP is
    spliced to `app-proxy`'s public listener, **not decrypted**.
  - Any other SNI, or none (IP clients, the console, ACME TLS-ALPN): raw TCP
    is spliced to the next owner. On App Access's adopted layout that is
    `app-proxy`, which still forwards the console. Otherwise it is Caddy.
- **Dedicated-IP mode** (the D.2 layout) stays supported, but it is no longer
  required.

**Client addresses: PROXY protocol v2 on every spliced connection.** The edge
prepends a v2 header carrying the real client address. Each receiver trusts it
only from the edge:
- **Caddy** (console, nginx, API: login throttling, rate limits, audit). The
  Local Sharing overlay puts `beam-proxy` and Caddy on a dedicated internal
  network `edge` with a fixed, operator-overridable subnet
  (`TUNNEX_EDGE_SUBNET`, default `172.31.254.0/29`). `beam-proxy` has the fixed
  address `.2`. Caddy's built-in `proxy_protocol` listener wrapper is enabled
  only when `TUNNEX_EDGE_PROXY_PROTOCOL_FROM` is set, and it allows exactly
  that `/32`. A header from any other source is never parsed, so the
  handshake fails. Client addresses cannot be spoofed.
- **`app-proxy`** (our code). It requires a PROXY v2 header that carries a
  pre-shared edge token TLV (32 random bytes from a private file mounted into
  both proxies). A connection that starts with a PROXY signature but has a
  missing or wrong token, or a malformed header, is closed (fail closed).
  Connections without a PROXY signature are served as before. This keeps the
  loopback console-forward and the dedicated-IP layouts working. No fixed
  address is needed, so App Access-only installs gain no new network.
- **`beam-proxy`** receives clients directly, so it sees real addresses.

**Readiness:** no change in substance. The probe already dials the real public
443 with a random `*.<sharing domain>` SNI. Through the edge, that SNI routes
to `beam-proxy`, which presents the sharing certificate and refuses the unknown
host. A test proves this through an edge.

**Independence:**
- Disabling Local Sharing returns 443 to its previous owner (the host command
  restores the saved `.env` values).
- App Access never needs the edge.
- Local Sharing needs App Access neither in Compose nor in code.

**Upgrade:** `upgrade.sh` admits the edge layout from `.env`, the same way it
admits ports. Stopping `beam-proxy` before migration briefly takes public 443
down during the control-plane restart, which already takes the console down.
If the new proxy fails to start, the refusal tells the operator to run
`tunnex-local-sharing disable`, which hands 443 back.

### E.2 One-step enable: `tunnex-local-sharing`

It is a host command in the style of `tunnex-app-access`. It is shipped in the
signed API image's host files, installed by the upgrade, and also runnable from
`docker compose cp`.

- **`enable --domain D --cert FULLCHAIN --key KEY`** (dry run by default;
  `--apply` to change). In order:
  1. verifies the installed signed release and pins `beam-proxy`;
  2. installs the managed overlay;
  3. issues the proxy credential with purpose `local-sharing` and the
     connector certificate, through the same one-off writable-lock helper the
     upgrade uses;
  4. installs the certificate files (0400, uid 10001);
  5. creates the edge token;
  6. writes `.env`, saving the values it replaces;
  7. brings the services up;
  8. prints what is left (DNS record, console check) in plain words.

  It is idempotent: a re-run with the same inputs changes nothing. It never
  prints secrets.
- **`disable`:** stops and removes the Local Sharing containers, restores the
  saved 443 owner and `.env` values, and revokes the Local Sharing proxy
  credential. Settings, policy, history and the restore volume are kept.
- **`status`:** reports what is installed and what is missing.

### E.3 Purpose-bound proxy credentials

- **Schema:** a migration adds
  `app_access_proxy_credentials.purpose text NOT NULL DEFAULT 'app_access'
  CHECK (purpose IN ('app_access','local_sharing'))`.
- **Enforcement:**
  - the App Access authority accepts only `app_access`;
  - `/internal/beam/*` accepts only `local_sharing`.
- **Issuing:** `backupctl app-proxy-issue --purpose app-access|local-sharing`
  (default `app-access`, so existing App Access tooling is unchanged).
- **Rollout:** every existing credential becomes `app_access`. No Local
  Sharing credential was ever issued for a supported install, because the
  signed proxy image ships with this branch. A hand-built Local Sharing proxy
  therefore stops authenticating after the upgrade, and the host command's
  `enable` re-issues a `local_sharing` credential. This is the safe direction:
  no credential silently gains authority, and App Access keeps working through
  the upgrade with no action.

---

## A.4 Final demo checklist (supersedes A.3; from the first release cut from this branch)

1. **Sharing domain** of its own registrable name, e.g. `tunnex-share.dev`.
2. **Wildcard certificate** for `*.tunnex-share.dev` (full chain + key).
3. **DNS:** `*.tunnex-share.dev` → the demo VM's existing public address. No
   second IP is needed.
4. **One command** in the install directory:
   `./tunnex-local-sharing enable --domain tunnex-share.dev --cert fullchain.pem --key privkey.pem`
   to review the plan, then run it again with `--apply`. Open TCP 8447 for
   publishers when it says so.
5. **Console:** Settings → Local Sharing domain (the printed values) → Check
   DNS and TLS, then the org policy and the Features switch.

**Demo upgrade afterwards:** the same `upgrade.sh --apply` or dashboard
button.
1. It verifies the signed `app-proxy` and `beam-proxy`.
2. It admits both overlays and the edge settings against `.env`, then backs up.
3. It stops `app-proxy` and `beam-proxy`. Public 443 is briefly down, together
   with the control-plane restart that already takes the console down.
4. It migrates the API and checks App Access authority.
5. It starts `app-proxy`, health-checks the API, then starts `beam-proxy`.
   That restores 443 for the console, App Access and shares.

If `beam-proxy` fails to start, the message gives
`./tunnex-local-sharing disable --apply`, which hands 443 back to the console
immediately.

**Precondition (unchanged):** the demo's App Access must be in the managed
layout first (AA-EN-1 E12). The command detects App Access only from the
managed `app-access.yml` plus its hash in `.env`.

## E.4 What was verified against real software (throwaway `lsux1-*` Docker only)

- **Caddy (pinned image v2.11.4), `proxy_protocol` wrapper with `allow <edge>/32`
  and `fallback_policy skip`:**
  - from the edge address, a PROXY v2 header sets the client address;
  - the edge without a header is served normally;
  - from any other address, a forged header breaks the handshake and is not
    trusted;
  - other direct callers are served normally.

  Every generated Caddy mode validates with the pinned image. This is now a CI
  contract (`deploy/edge-proxy-protocol-contract_test.sh`).
- **One-off `backupctl` helper mounts:** a Compose override that re-mounts
  `app_restore` with `read_only: false` replaces the serving overlay's
  read-only mount for the one-off run only. The serving composition stays
  read-only. The bind-mounted output directory is writable by uid 10001 once
  owned by it, which the host command does when run as root. Same mechanism as
  `upgrade.sh`'s `app-preflight` helper.
- **Not exercised live:** a full stack with a published `beam-proxy` image,
  because the image is produced by release CI. The edge, PROXY reader/writer and
  readiness-through-edge are covered by Go end-to-end tests over real TCP/TLS.

## E.5 Review folds and known limits

**Folded after review:**
- **Edge token scope.** The edge token goes only to `app-proxy`, which verifies
  it. Caddy trusts the edge by its fixed address and never receives the secret.
- **Edge bounds.** The edge never blocks accepting:
  - over a bound, a new stream is closed;
  - one source address can hold at most 8 handshakes in flight and 256
    splices;
  - a spliced stream with no traffic for 1 hour ends.

  A test proves a silent flood from one address does not stall another client.
- **Host command safety.**
  - It refuses unless the running stack is exactly the managed composition.
    An adopted or hand-written App Access layout is named, and nothing
    changes.
  - It requires root, so the proxy (uid 10001) owns its files.
  - If anything fails after `.env` changes, it restores the previous `.env`
    and overlay and brings the previous stack back up, so public 443 never
    stays without an owner.
- **Upgrade in edge mode.** On any failure after the proxy stopped, the
  upgrade starts it again so the console keeps 443. Shares stay unavailable
  until authority is current.
- **Copy-paste commands.** Every manual issuing command now passes
  `--purpose local-sharing`.
- **Verified on Compose 5.4.0:** `up -d --wait` with the one-shot
  `beam-restore-init` succeeds.
- **End-to-end check:** client → real edge (the `sniedge` package) → real
  pinned Caddy. Caddy reported the client's own address, not the edge's.

**Known limits (stated, not hidden):**
- **Client address on the demo's adopted App Access layout.** There,
  `app-proxy` terminates the console and forwards it to Caddy. Caddy does not
  trust `app-proxy` as a proxy, so the API sees `app-proxy`'s address. That is
  the case today, before this branch. The edge delivers the real address to
  `app-proxy` (so App Access audit is right), but not past it to the console
  API.
  - Fix: route console SNI straight to Caddy. That needs Caddy to hold the
    console certificate, which is an on-host check (AA-EN-1 S1 vs S2).
    Founder decision.
  - On base installs and on App Access installs where Caddy serves the
    console, the API sees real client addresses.
- **IPv4 only.** Edge mode publishes 443 on IPv4 (`0.0.0.0`). A host that
  served the console over IPv6 stops doing so on 443 until an IPv6 binding is
  added.
- **Not exercised live:** a full stack running the published `beam-proxy`
  image, `backupctl` itself inside the real API image, and `docker compose cp`
  from it. The helper mount semantics, the edge, Caddy and readiness were each
  exercised for real or end to end.

---

## F. Founder ruling 2026-11-25 (third): real client addresses at the console API

**Finding, worse than reported in E.5.** The API takes its client address from
chi `RealIP`. That uses, in order, `True-Client-IP`, then `X-Real-IP`, then
the leftmost `X-Forwarded-For`. nginx sets `X-Real-IP $remote_addr`, which is
always **Caddy's container address**. So today the API sees one address for
every client on **every** install, with or without App Access. Login
throttling and audit are per-Caddy, not per-client. Worse, a client-supplied
`True-Client-IP` passes through Caddy and nginx untouched, and `RealIP`
prefers it. **Any client can choose the address the API records.**

**Decision: fix the whole chain, keeping one rule: each hop trusts only the
previous hop.**

| Hop | Change | Trust |
|---|---|---|
| Single-IP edge → Caddy / `app-proxy` | unchanged (E.1): PROXY v2 | Caddy: edge `/32`; `app-proxy`: edge token |
| `app-proxy` → Caddy (console forward) | `app-proxy` already strips every client forwarding header and sets `X-Forwarded-For` to its peer (the real client, behind the edge too). Caddy now trusts that header **only** from `app-proxy`'s fixed address on the internal `edge` network (`trusted_proxies static 172.31.254.4/32`). | `/32` of `app-proxy` |
| Caddy → nginx | Caddy overwrites `X-Real-IP` with `{client_ip}` and deletes `True-Client-IP` in every mode. `{client_ip}` is the PROXY address, the trusted-proxy address, the load balancer's (terminated mode, unchanged) or the peer. | Caddy's view |
| nginx → API | nginx forwards Caddy's `X-Real-IP` instead of its own peer and always clears `True-Client-IP`. | nginx is internal-only |

**Why `X-Forwarded-For` from `app-proxy`, not PROXY v2.** `app-proxy` forwards
the console with an HTTP connection pool. A PROXY header belongs to a TCP
connection, so a pooled connection would carry the first client's address for
later clients. The fixes would be to turn pooling off (one TLS handshake per
console request) or to keep one pool per client. The header is set per
request and already exists in released `app-proxy` builds, so trust it by a
fixed address. The fixed address on an internal network is the same pattern
E.1 uses for Caddy.

**Network.** The App Access overlay now also defines the internal `edge`
network, identical to the Local Sharing definition so Compose merges them. It
gives Caddy `.3` and `app-proxy` `.4` fixed addresses there. Before any
backup, `upgrade.sh` refuses, with the exact `.env` line to set, if
`TUNNEX_EDGE_SUBNET` overlaps an existing Docker network. Otherwise the next
upgrade applies all of this with **no operator edits**, including on the demo
(managed `tunnex.yml` + `app-access.yml`).

**Version skew during the upgrade.** Caddy and nginx are recreated together
from the same release.
- **Old `app-proxy` with new Caddy:** works. Old `app-proxy` already sends the
  header.
- **New Caddy without its fixed address yet:** the header is simply not
  trusted, and the console still works.
- **New nginx with old Caddy:** possible only for the seconds between their
  recreation. A client `X-Real-IP` could then pass through, which only affects
  attribution. Nothing breaks.

**IPv6.** Edge mode publishes 443 on IPv4 only. A host that served the
console over IPv6 should keep `--layout dedicated`, or add an IPv6 publish
(documented; not automated).
