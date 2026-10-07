# Tunnex Beam epic and implementation plan

Status: **All 11 stories are implemented. Current runnable automated and Mac/local/AWS browser checks passed; full epic release acceptance remains open for physical platform, identity-provider, browser and deployment checks.** See [2026-10-07 acceptance results](BEAM-epic-acceptance-20261007.md) for current counts and story-by-story gaps. The local evidence below is the earlier 2026-10-06 snapshot; it does not describe current AWS delivery status.
Prepared: 2026-10-06. Epic: **BEAM**. Story namespace: **BM**.
Working feature name: **Tunnex Beam**. Description: **Share a local web app through a secure link**.
Scope extension, 2026-10-06: standalone CLI publishers are now included alongside desktop publishers. [CLI publishing](BEAM-cli-publishing.md) records commands, authority boundaries and local qualification. This extension does not change the existing 11-story acceptance count or imply a published CLI release.
Core planning baseline: `extra-feature`, `7ed12a91a2c4d4f9f0e7f30a3e6ae19eb5e219aa`.
Desktop source: `tunnexio/tunnex-client`, main pulled to `9b71d19ba1fc34a857c289a4ee6aa8b1368aba07`; isolated `extra-feature` worktree `/private/tmp/tunnex-client-beam`. Core worktree `/private/tmp/tunnex-beam-plan` keeps the primary `fix/web-publish-native-build` checkout untouched.

Current contract: [Beam authority and transport](BM-0-authority-contract.md). Persistent control-plane authority, the dedicated proxy, native desktop connector, desktop UI and console UI are implemented locally. Acceptance remains separate from implementation; the [current qualification matrix](BEAM-local-qualification.md) records every slice, measured proofs and remaining browser/platform/deployment checks.

## Current local implementation evidence

| Stories | Implemented locally | Remaining acceptance |
| --- | --- | --- |
| BM-0 | **Locally accepted.** Separate authority/transport contract; native HTTP/SSE/WebSocket; real Electron and PKCE; Mac ARM64/Windows x64 package contents; nonroot TLS TCP 443; actual authenticated HTTPS reviewer reaches the Mac app with VPN disconnected | Later platform/public-certificate qualifications remain in BM-5/BM-10 |
| BM-1 | Default-off organization policy, audience and TTL/quota constraints; saved versioned operator installation and organization policy; five independent real DNS/TLS checks; policy impact preview/Cancel/focus return; actual HTTPS publisher/reviewer walkthrough | Live policy-change impact confirmation beyond the approved setup |
| BM-2 / BM-3 | Persistent idempotent share creation, scoped connector certificate, fixed loopback target, generation fencing and live-channel readiness; desktop create/runtime integration | Real user walkthrough and full credential/account-switch matrix |
| BM-4 | Current browser-parent/grant authority, nonce-bound one-use launch, isolated proxy cookies; Shared with me and launch UI; actual normal HTTPS login/Continue reaches origin HTML | Full SSO/MFA and hostile-content browser isolation qualification |
| BM-5 | Concurrent native HTTP/SSE/WebSocket; real Vite edit/update/refetch; directional streaming frame/message/fragment limits and upgrade-head checks; verified numeric-SAN HTTPS origins, wrong certificate denial; immediate oversized upload rejection | Actual authenticated browser Vite DOM update and complete application/browser compatibility matrix |
| BM-6 / BM-7 | Real desktop create/copy/open/pause/resume/stop/extend/access impact actions; server search/pagination, audience counts and server-clock countdown; four-second leases; 31 distinct persistent native withdrawal/outage cases across multiple focused runs | Final latest-build browser/desktop management walkthrough; complete account/server/org-switch UI matrix |
| BM-8 | Reconnect fencing, tray/quit lifecycle, supported restore revocation and domain-withdrawal checks | Sleep/wake, outage and complete recovery qualification |
| BM-9 | Transactional lifecycle audit; retained admission evidence in existing Access Events; event filters, owner history and redacted diagnostic export; authoritative owner quota independent of visible rows; fair cleanup; per-org/share bounds; TLS/lease metrics; real slow-reader plateau and concurrent serving | Latest retained access evidence browser walkthrough; certificate rotation and final operational/deployment matrix |
| BM-10 | Disposable local CP/gateway/proxy stack, generated Beam contracts, Mac ARM64/Windows x64 local packages; optional confined Compose override with six rendering/security tests; actual nonroot Beam Docker image serving | Native Windows runtime/install, full deployment upgrade/rollback and complete customer acceptance |

The local console is `http://127.0.0.1:18283`; raw API is port `18284`; console development UI is port `15173`. The native desktop dev application uses the console on `18283` with an isolated development profile. Local TLS fixtures and bootstrap credentials are private ignored runtime files. They are not production domain or certificate qualification.

## Epic and customer outcome

A developer opens Beam in the Tunnex desktop client, chooses a local web app port, selects permitted teammates and an expiry, then creates an HTTPS link. A reviewer signs in through a browser and opens the app. The publisher manages access, pauses, resumes or stops the share. Access ends when the share expires or its authority is withdrawn.

An installation operator configures the serving domain and TLS once. An organization administrator enables Beam and delegates publishing within a sharing policy. Authorized developers then share apps without asking the administrator for each link. Creating previews does not require a separate CLI installation or an active VPN connection.

| Epic field | Plan |
| --- | --- |
| Customer problem | Local app reviews require deployment, screen sharing or ad hoc tunnels without the organization's access controls. |
| Publisher | Authorized existing Tunnex member using the desktop client or standalone CLI. |
| Reviewer | Existing organization member with a current explicit user/group grant; browser only. |
| Product surfaces | Desktop Beam; standalone CLI; web Beam with My shares and Shared with me; operator setup and organization policy in existing settings. |
| Main journey | Sign in → Beam → Share local app → port → reviewers → expiry → create link → review → stop or expire. |
| Authority | Organization policy, publisher identity, connector identity, share revision, current reviewer grant and current reviewer login. |
| Scope | 11 stories, 31 slices, including feasibility and release qualification. |
| Completion | A qualified desktop-to-browser journey, bounded revocation, supported HTTP/HMR behavior, documented limits and upgrade/recovery evidence. |

## First release scope and defaults

These are proposed implementation defaults. BM-0 locks the authority contract, supported topology, numeric limits and transport choice before dependent implementation.

| Area | First release decision |
| --- | --- |
| Publisher interface | Desktop connector or standalone foreground CLI connector. CI service identities and unattended publishing remain outside this extension. |
| Reviewer interface | Browser login through existing local authentication or configured SSO. No client installation. The app's own login may still apply. |
| Shield boundary | Beam is a separate developer sharing feature. The publisher runs a desktop or CLI connector, so Beam does not meet the agreed fully clientless Shield product definition. |
| Local target | One HTTP or HTTPS app on an explicitly selected numeric loopback address and port per share. No remote destinations, LAN hosts, arbitrary TCP or CONNECT. |
| HTTP and HTTPS | HTTP over laptop loopback is supported. HTTPS requires a verified local certificate identity or an explicitly configured trust anchor; no global insecure TLS toggle. |
| Runtime | Prefer a bundled unprivileged connector supervised by Electron main. BM-0 selects a reusable implementation after proving HTTP, SSE and WebSocket transport. No privileged VPN helper requirement for Beam. |
| Connectivity | Publisher initiates an authenticated outbound connection over a qualified TLS transport on port 443. Reviewer connects to the reachable preview proxy. No new inbound laptop listener. |
| Sharing | Existing users/groups allowed by organization policy. Creator is added as an explicit initial reviewer, subject to the same login and access rules. External guests and anonymous links are deferred. |
| Delegation | Publishing permission authorizes bounded reviewer grants on the creator's own shares, inside the administrator's allowed audience. It does not authorize granting Beam to arbitrary users. |
| Expiry | Default 2 hours; proposed organization maximum 24 hours. Compute expiry from successful share creation using server time. Never reset expiry on reconnect or resume. |
| Extension | Explicit owner action within current policy and a hard lifetime ceiling of creation time plus the organization maximum. A later policy reduction caps existing shares. |
| Publisher limits | Proposed maximum 5 nonterminal shares per publisher. Starting, active and paused shares all consume quota. |
| Domain | One installation-controlled Beam base domain, with exact hostnames unique across tenants. Prefer a separate registrable domain from the control plane. Reuse only qualified domain boundary rules. |
| URL | `https://p-<random-id>.<beam-base-domain>`. Use at least 128 bits of cryptographic randomness. The ID is a locator, not an access credential. |
| DNS and TLS | Operator-provided wildcard DNS and supported wildcard TLS termination, with readiness checks. No per-share DNS work. Automated domain purchase, DNS provisioning and unrestricted certificate issuance are outside v1. |
| Lifecycle | Starting → active ↔ paused → stopped, expired or revoked. Terminal shares cannot be resurrected. Connectivity is a separate online/reconnecting/offline/origin-unavailable projection. |
| Stream authority | Every new request requires current authorization. Active HTTP transfers, SSE and WebSockets renew bounded leases; proposed maximum 5-second stale-authority window. A lost notification does not extend it. |
| Availability | One qualified proxy instance and one publisher connector per share. Reconnect opens a new generation; existing streams are closed. No transparent stream migration or multi-proxy HA promise. |
| Data | Retain safe operational/access metadata under existing retention policies. No persisted request/response bodies, raw query strings, cookies or application secrets. |
| Commercial gate | Beam capability and organization opt-in default off. Final tier mapping is a BM-0 decision; the plan does not promise a SKU or change existing group availability. |

Content already delivered cannot be recalled. Closing a stream cannot undo an application mutation that the origin has already accepted.

## Source reuse and new responsibilities

| Existing source or behavior | Reuse | Beam work |
| --- | --- | --- |
| Client `apps/client/src/main/credential.ts`, `session.ts`, `managedlifecycle.ts` | Account/server binding, secure credential handling, protection against stale operations | A separate Beam publishing authority and connector identity; no assumption that VPN enrollment authorizes publishing |
| Client `apps/client/src/main/ipc.ts`, `src/preload/index.ts`, renderer `apps/web/src/lib/desktop.ts` | Verb-specific IPC, sandboxed renderer, typed bridge | Beam create/list/status/pause/resume/stop/access methods; secret-free status events |
| Client `apps/web/src/client/ClientApp.tsx`, `apps/client/src/main/index.ts`, `tray.ts` | Desktop shell, app lifetime, tray and guarded quit | Beam navigation and independent runtime; the current client UI has no Beam surface and non-macOS window closure currently quits the app |
| Core users/groups, RBAC, local/SSO auth, MFA | Existing actor identity and factor verification | Dedicated permissions, delegated audience rules, scoped publishing bootstrap and reviewer grants |
| Core `apps/api/internal/appaccess`, `apps/app-proxy`, `packages/apptransport` | Qualified launch, reverse-proxy, lease and framing patterns | Distinct Beam resource, route audience and laptop connector binding. Existing gateway/app grants do not authorize Beam. |
| `packages/apptransport/originpolicy/policy.go` | Preserve App Access's existing destination restrictions | A separate tightly scoped laptop loopback policy. Existing App Access refuses `127.0.0.0/8` and `::1/128`; do not weaken that policy. |
| `apps/api/internal/http/app_access_session_handlers.go` | Human browser launch and own-session revocation patterns | Separate publisher APIs. Existing App Access browser-session handlers reject bearer-based own-session use. |
| `apps/api/internal/appdomains/settings.go` | Domain validation and installation-level configuration patterns | Beam domain namespace, collision prevention, readiness and migration rules; arbitrary CP sibling-domain use is not assumed safe |
| Core Audit Log, Access Events and alerts | Existing permissions, filters, retention and delivery | Beam event producers, filters and safe health/capacity metrics |
| Core OpenAPI, migrations, Compose/Helm/install and client packaging | Contract generation and release conventions | Beam capability negotiation, optional runtime wiring, bundled connector, upgrade and rollback qualification |

Paths above describe integration candidates, not implemented Beam capabilities. Desktop changes belong in `tunnex-client`; control plane, web console and proxy changes belong in `tunnex`.

## UI surfaces and role boundaries

| Surface | UI and visible actions | Authority boundary |
| --- | --- | --- |
| Desktop Beam | Share local app; own active shares; port, reviewers, expiry, link and status; Copy link, Open, Manage access, Pause, Resume, Extend and Stop | No raw bearer/connector secrets in the renderer. Beam status remains separate from VPN status. |
| Desktop tray | Active share count; Show Beam; explicit Quit behavior and a warning when sharing will end | Closing the window may keep sharing only when the app remains running under the qualified platform behavior. |
| Web My shares | Owner inventory, live state, expiry, access and lifecycle actions | Browser can manage an existing share but cannot start a local laptop connector by itself. |
| Web Shared with me | Permitted shares, publisher, expiry and Open | Show only current authorized shares. No laptop address, local port or other reviewers' grants. |
| Web Settings | Organization enablement, publisher groups, allowed audience, maximum duration and quotas | Organization administrators control their own policy. Installation domain/TLS settings require installation-operator authority. |
| Reviewer browser | Login, optional inline MFA, then app; dedicated denied/paused/offline/expired pages with safe recovery | No content grant implied by admin role or ownership. Do not inject a control toolbar into arbitrary app HTML in v1. |
| Audit Log and Access Events | Beam filters, actor, action, outcome, reason, time and share ID | Reuse existing audit/event read permissions. Management does not imply app-content access. |

Proposed web routes: `/beam`, `/beam/my-shares`, `/beam/shared-with-me`, `/beam/shares/:shareId`. These are new Beam routes, not changes to Shield navigation. Every screen supports loading, empty, permission denied, stale, unavailable and retry states; a failed fetch must never appear as an empty list.

## Story overview

| Story | User story and deliverable | Priority | Slices | Prerequisites |
| --- | --- | --- | --- | --- |
| BM-0 Authority and feasibility | As the product team, prove a bounded desktop-to-browser design before committing to the transport and UI. | P0 | 2 | None |
| BM-1 Domain and organization setup | As an operator/admin, configure Beam once and delegate safe self-service publishing. | P0 | 3 | BM-0 |
| BM-2 Create a local share | As a developer, select a port, permitted reviewers and expiry and create one share without duplicate resources. | P0 | 3 | BM-0; BM-1 policy/domain contracts |
| BM-3 Desktop connector | As a developer, share through an outbound connector while the VPN is disconnected. | P0 | 3 | BM-0 transport; BM-2 share contract |
| BM-4 Reviewer browser access | As a teammate, sign in and open only shares currently granted to me. | P0 | 3 | BM-1; BM-2; BM-3 |
| BM-5 Web app and HMR compatibility | As a developer/reviewer, use assets, forms, streaming and live reload within documented app limits. | P0 | 2 | BM-3; BM-4 |
| BM-6 Share management | As a publisher, manage my shares and allowed audience from desktop and web. | P0 | 3 | BM-2; BM-4; lifecycle contract |
| BM-7 Expiry and continuous authority | As an admin/publisher, have expiry and withdrawal cut off new and already-open access within the bound. | P0 | 3 | BM-3; BM-4; BM-6 |
| BM-8 Recovery and desktop lifetime | As a developer, understand failures and safely recover without changing permissions or extending the link. | P0 | 3 | BM-3; BM-6; BM-7 |
| BM-9 Audit and operational limits | As an operator/admin, see safe access evidence and keep sharing within capacity. | P0 | 3 | Core contracts; emitted by every implementation story |
| BM-10 Qualification and release | As the product owner, review a tested feature with install, upgrade and recovery evidence. | P0 | 3 | BM-0 through BM-9 |

Slice IDs are planning identifiers. They are not external Jira issue keys. Backend authorization, negative tests and audit events are part of each producing slice; BM-7 and BM-9 qualify the combined behavior rather than postponing those controls.

## BM-0 Authority and feasibility

**Story:** As the product team, we need an agreed authority contract and a real transport spike so that the product does not depend on an unproven proxy or desktop lifecycle.

| Slice | UI tasks | Frontend tasks | Backend and connector tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- |
| **BM-0a Authority and journey contract** | Define publisher, reviewer, organization admin and installation operator journeys; sketch create, live, denied, paused, offline and expired states. | Desktop/web fixture prototypes; define typed state/action envelopes and frontend visibility rules. | Decision record covering permissions, audience delegation, publishing bootstrap, MFA proof, publisher logout/expiry, leases, domains, numeric limits, feature gates and rollback. Define authority separately from transport status. | Reviewed contract resolves who may create/open/manage, every terminal trigger and the supported domain topology. No implied admin-content access or VPN-enrollment requirement. No prerequisites. |
| **BM-0b Native transport spike** | Prototype connection progress, local app unavailable and incompatible-app guidance. | A disposable desktop main/preload/renderer path showing genuine connector state; browser fixtures for a basic app and Vite HMR. | Prove outbound TLS 443 → proxy → bundled unprivileged connector → fixed loopback port; authenticated connection generations, HTTP, SSE, WebSocket, cancellation, wrong identities and revoked leases. Select runtime/library reuse; package the spike on macOS and Windows. | Allowed reviewer reaches the app with VPN disconnected and no privileged helper. Unauthorized/replayed connector cannot bind. Lost CP authority closes streams within the target. Choose the transport before dependent slices. Depends BM-0a. |

## BM-1 Domain and organization setup

**Story:** As an operator and organization administrator, I can configure the serving address once and let permitted developers create shares within policy.

| Slice | UI tasks | Frontend tasks | Backend and connector tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- |
| **BM-1a Serving domain readiness** | Operator setup form/checklist with base domain, proxy endpoint, DNS/TLS readiness and concise repair states. Organization UI shows readiness without operator-only controls. | Core web configuration/readiness views; versioned save/check, loading/error state and disabled publishing when setup is not ready. | Installation-level domain registry and RBAC; validate qualified boundary, wildcard DNS/edge TLS, exact approved Host routing and cross-tenant uniqueness. Model certificate/domain changes with explicit impact. | Unconfigured, wrong DNS, invalid/expired TLS, unknown Host and prohibited CP-domain topology cannot become ready. No arbitrary Host-driven certificate issuance. Depends BM-0. |
| **BM-1b Publisher and audience policy** | Organization settings for enablement, permitted publisher groups, allowed reviewer audience, maximum duration, quotas and optional MFA requirement. Explain that normal creation is self-service. | Core web policy form, safe user/group selector, effective capability projection and conflict recovery. Desktop consumes the same policy envelope. | Organization-scoped policy schema/API and dedicated create/use/manage-own/manage-all/audit permissions; default deny/off; grant delegation intersection; revision and transactional audit. Safe directory projection supports selection without requiring full user administration. | Member cannot change policy or search an unauthorized audience. Allowed developer can create without per-share admin approval. Hidden controls are backed by server rejection. Depends BM-0a. |
| **BM-1c Enable and policy change behavior** | Enable/disable and policy-change impact confirmation with affected share counts; members receive a clear availability reason. | Wire setup state and policy availability into desktop/web navigation; refresh capability after changes; retain specific denial reasons. | Feature/entitlement/capability gates; re-evaluate active shares on publisher/audience/TTL changes; disabled organization/domain withdrawal denies new requests and revokes active authority. | Disable and reduced policy affect existing HTTP/SSE/WebSocket access within the authority bound, without changing App Access policy. Domain change requires draining affected shares; old links never silently retarget. Depends BM-1a/b; full stream proof in BM-7. |

## BM-2 Create a local share

**Story:** As a permitted developer, I choose my local app, who can review it and how long the link remains valid, then create one share.

| Slice | UI tasks | Frontend tasks | Backend and connector tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- |
| **BM-2a Desktop Beam and local check** | Add Beam alongside the existing connection controls. Create dialog: app name, numeric loopback family, port, HTTP/HTTPS and Check app; accessible field errors and Ready/Unavailable states. | Client renderer Beam shell/form; typed `beam.checkLocal` IPC; stale-check invalidation on target changes; no arbitrary URL or shell command field. Keep existing connection surface usable. | Main-process input validation and fixed-address local probe with short timeout; require account/capability and pin server/user/org operation context. HTTPS verifies configured trust. Do not execute commands or auto-scan local services. | Invalid/non-loopback target, port, untrusted TLS and local timeout show actionable errors. Target edits invalidate earlier checks. Signed-out or forbidden users cannot probe through privileged IPC. Depends BM-0 and BM-1b. |
| **BM-2b Reviewers and expiry** | Audience selector, creator's explicit initial grant, expiry choices within policy and confirmation of who can open the link. | Fetch safe allowed-directory options; reviewer chips/group selection, server-clock countdown inputs and validation. Preserve input on recoverable errors; block stale audience submissions. | Validate current actor, policy, group/user scope, duration and grant bounds at commit time. Define local-target revision and per-request idempotency key. Enforce quota transactionally. | Tampered audience or excessive TTL is rejected server-side. Group membership is evaluated at access time. No silent Everyone grant and no browser-session assumption for desktop bearer auth. Depends BM-2a and BM-1b. |
| **BM-2c Create and publication progress** | Show Creating → Connecting → Ready; reveal Copy link/Open when serving readiness is established; failure view with retry/stop. | `beam.create`, progress subscription, idempotent retry after network loss, server-confirmed URL/expiry; web can inspect the resulting owner record. Never infer Ready from a local open port. | Beam resources/grants/migrations/OpenAPI; atomic creation/audit and random host reservation; separate short-lived publishing bootstrap scoped to actor/org/share/connector. Exchanging it requires the correct connector key. Activation requires current authority and end-to-end readiness. | Concurrent retries produce one share, one hostname and one grant set. At least 128-bit random IDs; globally unique exact hosts. Failed startup releases authority/quota after a bounded deadline. Depends BM-2b; activation integrates BM-3. |

## BM-3 Desktop connector

**Story:** As a developer, my installed desktop client publishes the selected local app through a separate authenticated runtime without requiring a VPN connection.

| Slice | UI tasks | Frontend tasks | Backend and connector tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- |
| **BM-3a Connector bootstrap and binding** | Connection progress, reauthentication required, unsupported server/client and secure-storage unavailable states. | Typed Beam bridge/main API client; secret-free runtime summaries and error mapping; server/account/org switch cancels pending operations. | Bundled connector supervisor; generate proof-of-possession identity, exchange narrowly scoped bootstrap and establish current serving generation. Bind server, org, actor, share, target revision, expiry and protocol version. Keep account token and connector credentials out of renderer/logs. | Wrong key, foreign tenant, replay, stale revision, machine token and expired publishing authority cannot connect. Beam credential storage requires secure storage or an explicitly supported memory-only mode. Depends BM-0b and BM-2c. |
| **BM-3b Outbound serving and loopback boundary** | Show Online versus local app unavailable; desktop detail displays the selected local target to its owner. | Subscribe to connector/origin readiness; render failures independently from VPN status; prevent stale state from marking a stopped share Live. | Dedicated Beam route/transport audience and connector loopback-only dialer. Every stream maps to one immutable target; reject absolute-form URLs, CONNECT, destination overrides and unauthorized revisions. Do not follow redirects by dialing a new host. Preserve App Access's existing origin policy. | Proxy cannot reach its own loopback or any publisher LAN/metadata target through Beam. Verified app requests work with VPN disconnected. Malicious request targets and cross-share stream IDs fail closed. Depends BM-3a. |
| **BM-3c Serving heartbeats and generations** | Starting, online, reconnecting and offline status with last successful contact; avoid misleading Live when origin/authority is absent. | Desktop status push and bounded web status refresh; maintain ordered revision/generation snapshots; ignore late replies after account/server/share changes. | Bounded heartbeats, startup timeout, serving readiness report and exclusive connector generation; validate current authority on heartbeat/renewal. Old generations and their streams are terminated before replacement serves. | Two connectors cannot concurrently own one share. Late heartbeat cannot revive stopped/expired/revoked shares. Lost connector becomes offline within the documented detection bound. Depends BM-3b. |

## BM-4 Reviewer browser access

**Story:** As an authorized teammate, I can open a link in my browser with existing Tunnex authentication while denied users receive no application content.

| Slice | UI tasks | Frontend tasks | Backend and connector tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- |
| **BM-4a Login and scoped launch** | Local/SSO sign-in and optional MFA step-up with a safe return to the requested share; generic denied/unknown link state. | Core web launch route, existing authentication/step-up UI reuse and allowlisted same-share returns. No custom factor enrollment for each share. | Human-browser admission; short-lived one-use launch exchange tied to exact share/host/parent session, nonce and current grant. Issue host-only secure browser session; enforce CSRF and separate Beam audience. Validate MFA policy against verified assurance. | Local and configured SSO flows work. Bad return URLs, replayed codes, absent membership, bearer-only reviewer requests and unknown MFA assurance cannot launch. Depends BM-1, BM-2 and BM-3. |
| **BM-4b Shared with me and Open** | Reviewer inventory with name, publisher, expiry, availability and Open; distinguish no shares from permission/load failures. | Core web Beam routes/navigation, search/pagination, loading/empty/error/expired states and server-derived Open availability. Add screen census entries. | Tenant-scoped safe reviewer projection; current user/group grants and readiness; no local endpoint or unrestricted directory leakage. Management role does not imply content access. | User sees only currently permitted shares; foreign IDs return safe errors. A removed group member loses access to future requests and live streams under BM-7. Depends BM-4a. |
| **BM-4c Browser session and cookies** | Dedicated paused/offline/origin-unavailable/expired/revoked pages; session expired offers safe re-login only when the share is still eligible. | Accessible error/recovery pages on qualified preview hosts; same-share relative path return; Open in system browser from desktop without privileged bridge. | Enforce grant, publisher, org, share, parent-login and MFA authority for every request; strip Tunnex credentials before origin forwarding. Qualify cookie scoping, CSRF, CSP, framing, service workers and hostile app-content isolation from CP and other shares. | Preview content cannot obtain CP credentials or launch another share. Logout and authority loss invalidate the session. Unsupported domain topologies stay blocked. Depends BM-4a/b; full stream checks in BM-7. |

## BM-5 Web app and HMR compatibility

**Story:** As a developer and reviewer, I can review a supported web app and see local changes without a deployment.

| Slice | UI tasks | Frontend tasks | Backend and connector tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- |
| **BM-5a HTTP application behavior** | Compact app compatibility guidance and specific local-server/host/TLS repair hints; keep diagnostics off the app's normal successful flow. | Owner Help panel and typed origin errors; rendered fixture flows for assets, forms, cookies, redirects and bounded uploads/downloads. | Qualify trusted forwarding headers, app Authorization handling, cookie boundaries, redirect rules, body/time limits and backpressure. Pin loopback destination regardless of Host. Strip only Tunnex credentials; app-specific authentication remains possible under the contract. | Root-path apps, assets, forms and local app login work; no Tunnex secrets reach origin. Unsafe cookie domains/external redirects cannot leak credentials. Document base-URL/Host configuration requirements; no universal HTML rewriting. Depends BM-3 and BM-4. |
| **BM-5b WebSocket SSE and live reload** | HMR-ready compatibility status/help; explain when a dev server needs an allowed host or public WebSocket URL. | Vite and one representative application fixture; browser E2E observes an actual local edit; recoverable stream failure states without claiming transparent replay. | Qualify upgrades, Origin/Host checks, SSE flush, bounded WebSocket frames and slow-consumer cancellation under the same session/route leases. No bypass endpoint for development sockets. | Live reload, SSE and long transfer work within bounds. Pause/revoke/expiry disconnect every supported stream protocol; malformed upgrades and oversized frames are rejected. Depends BM-5a; withdrawal matrix in BM-7. |

## BM-6 Share management

**Story:** As a publisher, I can inspect and manage my shares from desktop or web without granting myself wider organization permissions.

| Slice | UI tasks | Frontend tasks | Backend and connector tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- |
| **BM-6a Owner inventory and detail** | My shares table/detail with app name, local target on desktop, status, expiry, audience count, Copy link and Open. | Desktop and core web inventory/detail, safe clipboard/system-browser handlers, paging/search and live server-clock countdown; no failed fetch shown as zero shares. | Own-share versus manage-all projections; versioned resource APIs and safe status. Browser owner detail does not expose connector secrets or trigger a local probe. | Ordinary publisher cannot inspect or manage another owner's share. Admin can manage without receiving content access. Copy/Open uses the canonical server-issued HTTPS host. Depends BM-2 and BM-4. |
| **BM-6b Bounded audience management** | Manage access dialog with users/groups, expiry and remove confirmation showing affected sessions. | Desktop/web add/remove-grant actions with policy-limited selection, revision conflicts and refresh; preserve specific denial reason. | Versioned bounded grant create/remove, current delegation checks and atomic audit. Grant lifetime cannot exceed share lifetime. Removing a grant triggers authority re-evaluation; no owner bypass. | Owner cannot expand outside current allowed audience. Removed reviewer streams close within the bound; other eligible reviewers continue. Overlapping grants are evaluated correctly. Depends BM-6a, BM-1b and BM-4. |
| **BM-6c Pause resume stop and extend** | Clear action states; Stop confirmation; expiry extension selector inside remaining policy ceiling; paused versus offline distinction. | Desktop/web action handlers, pending-state disabling, stale conflict recovery and server-confirmed transitions. Resume retains URL; a terminal share offers Create new share. | Transactional state machine with expected revision/idempotency. Pause denies and closes serving; Resume requires current publisher/reviewer authority, target readiness and a fresh generation. Stop is terminal; extension is explicit and policy bounded. | Racing stop/resume/extend cannot reopen a terminal share or overrun TTL. Pause/resume preserves URL and original expiry. Browser resume can request state but cannot bypass an absent laptop connector. Depends BM-6a and BM-3; full enforcement in BM-7. |

## BM-7 Expiry and continuous authority

**Story:** As a publisher or administrator, I need access withdrawal to affect already-open traffic as well as new page loads.

| Slice | UI tasks | Frontend tasks | Backend and connector tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- |
| **BM-7a Expiry and durable cleanup** | Server-time expiry countdown and terminal status; clear Create new share recovery instead of automatic resume. | Desktop/web expiry projection survives reload; stop local serving on terminal events while retaining history. | Enforce expiry in request/lease decisions independently of cleanup jobs. Durable idempotent sweeper removes active routes, invalidates credentials, releases quota and retains audit/tombstone history; reconcile after crashes. | At expiry, new admission fails immediately and existing streams close by lease deadline. Sweeper outage cannot extend access. Retries/crashes do not leak quota or restore credentials. Depends BM-3, BM-4 and BM-6. |
| **BM-7b Reviewer and publisher withdrawal** | Safe reason-specific terminated status for owner/reviewer; admin impact view identifies affected share counts without showing content. | Desktop sign-out/account/server/org-change integration cancels Beam operations and tears down local serving; web reacts to revoked sessions/grants. | Current authority checks and lease withdrawal for reviewer logout, factor freshness, grant/group/membership loss; publisher sign-out/token expiry/revocation/group/role/membership loss; organization disable and entitlement/domain withdrawal. Source authentication family revocation must be traceable for desktop publishing credentials. | Every trigger is tested against new HTTP plus open transfer/SSE/WebSocket. Reviewer removal affects only users no longer authorized. Publisher authority loss terminates that publisher's shares. Depends BM-7a and BM-6b/c. |
| **BM-7c Authority outage and stale generation** | Authority unavailable/reconnecting status and safe retry; distinguish this from missing permission. | Clear prior Live projection when authority cannot be confirmed; ignore out-of-order updates and retry only nonterminal eligible shares. | No positive authorization cache for new requests. Bounded leases fail closed on CP/session-store outage; notifications accelerate withdrawal but are not sole authority. Reject replayed launch/connector/stream capabilities and old generations. | Dropped push, CP outage, session-store outage, clock skew, proxy restart and replay all preserve the agreed maximum stale-authority bound. Terminal shares never reconnect. Depends BM-7a/b. |

## BM-8 Recovery and desktop lifetime

**Story:** As a developer, I know whether my app is sharing and can recover from connectivity or app failures without silently changing the URL, permissions or expiry.

| Slice | UI tasks | Frontend tasks | Backend and connector tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- |
| **BM-8a Connectivity and origin recovery** | Distinct network offline, reconnecting and local app unavailable states; Retry and Check app with useful next actions. | Desktop/web recovery actions and ordered status refresh; show retained URL/expiry; avoid a retry storm. | Bounded reconnect backoff/jitter; authenticate each reconnect against current state and create a fresh exclusive generation. Local app health can recover only on the same immutable target; target change requires a new share in v1. | App stop/start and network drop/recovery preserve URL and expiry while nonterminal. Existing streams end; app protocols may reconnect normally. Expired/revoked shares stay closed. Depends BM-3, BM-6 and BM-7. |
| **BM-8b Tray window close and quit** | Desktop tray active-share count, Show Beam and Quit warning; explain that full app exit ends availability. Choose and document Close to tray behavior on supported platforms. | Beam app-lifetime singleton, renderer resubscription, tray wiring and safe quit/sign-out orchestration; review macOS and Windows behavior. | Runtime remains independent from VPN connect/disconnect. Orderly quit terminates local connector and attempts bounded server stop; abrupt exit falls back to server heartbeat/lease withdrawal. Preserve existing device/tunnel teardown rules. | Closing/reopening window does not create duplicate connectors. Qualified Close to tray keeps sharing; explicit Quit tears it down. Crash never leaves a serving orphan. Existing VPN connect/disconnect/removal behavior passes regression checks. Depends BM-8a and BM-7. |
| **BM-8c Restart and version compatibility** | Recovered shares require an explicit Resume/reauth action; client/server update-required and unsupported-feature states. | Secure local record of nonsecret share IDs and ownership; server reconciliation on startup; no automatic resurrection after full exit. | Runtime capability negotiation, minimum compatible versions and installation generations. Reconcile orphaned records and closed shares; renew connector identity only after fresh authority. | App restart cannot resurrect a stopped/expired share. Account/server switch does not load another identity's connector. Older clients/servers fail with supported messages while existing VPN remains usable. Depends BM-8b. |

## BM-9 Audit and operational limits

**Story:** As an administrator or operator, I can understand Beam access and failure reasons while keeping the proxy, laptop and organization within supported limits.

| Slice | UI tasks | Frontend tasks | Backend and connector tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- |
| **BM-9a Audit and access evidence** | Add Beam filters and details to existing Audit Log/Access Events; share history shows lifecycle and access outcomes, not app content. | Core web event filters/paging and owner-safe history; update screen census and permission states. | Typed lifecycle/policy/grant/auth/session/connector events with org/actor/share/revision/generation and safe reason; transactional mutation audit; bounded delivery/retention. Redact bodies, raw URLs/query strings, tokens, cookies and credentials. | Tenant/RBAC/retention tests pass. A sample request containing secrets leaves none in logs/events. Traceable evidence distinguishes creator, reviewer and operator actions. Event production is required in earlier slices. |
| **BM-9b Quotas capacity and backpressure** | Clear share-limit, stream-limit, upload-limit and capacity messages with relevant recovery; policy displays actual enforced limits. | Map typed 429/limit errors; prevent client retry floods; show active-share quota without fabricating bandwidth billing. | Enforce per-publisher/org/proxy/connector reservations, request/frame/body/time limits and bounded buffers; proposed 32 concurrent streams per share, final total limits from BM-0/load proof. Release reservations on all terminal/cancel/crash paths. | Parallel creates cannot exceed quota; slow consumers and oversize payloads stay within measured memory/CPU limits; tenant cannot exhaust another tenant's reserved capacity. Depends BM-2/3/5/7. |
| **BM-9c Health certificate and disable operations** | Existing operator health/help shows proxy/domain/TLS failures and safe diagnostics; optional existing-channel alerts for actionable sustained failures. | Redacted diagnostic export, health/status filters and approved certificate/maintenance impact views; avoid desktop credential export. | Metrics for authority lease failures, active streams, connector/origin readiness, rejected traffic, expiry lag, TLS expiry and capacity; optional alerts through existing integrations. Runbook for domain/cert rotation, disable/drain, cleanup retries and incident diagnosis. | Certificate expiry, rejected bootstrap, capacity saturation and disable/drain produce safe, actionable status. Logs/exports contain no credentials. Restored backups cannot re-enable old serving credentials. Depends BM-1/7/8. |

## BM-10 Qualification and release

**Story:** As the product owner, I can review evidence that Beam works on its supported topology and can be installed, upgraded and disabled safely.

| Slice | UI tasks | Frontend tasks | Backend and connector tasks | Acceptance and dependency |
| --- | --- | --- | --- | --- |
| **BM-10a Security and end-to-end qualification** | Review actual admin setup, publisher and reviewer flows; desktop/window/tray and 390px web layouts; keyboard/focus/error states. | Desktop IPC/state/lifecycle tests; core web full typecheck/tests/build; screen census; real rendered local/SSO/MFA allowed/denied flows and HMR review. | Relevant API/proxy/transport suites with isolated PostgreSQL/session store, tenant/authority/replay/SSRF/domain tests, generation checks and full protocol withdrawal matrix. Desktop package tests on macOS and Windows. | Evidence tied to exact core/client SHAs; native connector/proxy and real browser app behavior, not fixture-only success. All stories' negative acceptance cases pass. Depends BM-0 through BM-9. |
| **BM-10b Installation upgrade and rollback** | Operator/client setup and update instructions; supported-platform/version matrix and disabled-feature messaging. | Validate packaged desktop renderer/main/connector contracts; real install/update walkthrough on supported platforms; prevent obsolete cached state from claiming readiness. | Bundle/provenance checks; optional proxy service/config wiring in supported Compose/Helm/installer path; migration/backup/restore and compatible rollback tests. Fresh/upgrade default off; no cloud provisioning implicit. | Fresh install, opt-in upgrade, connector/proxy restart, certificate rotation, disable and rollback are proven. Restore starts non-serving until fresh identities and authority are established. Existing App Access/VPN/Shield flows remain qualified. Depends BM-10a. |
| **BM-10c Product walkthrough and handoff** | Customer walkthrough: configure once → developer share → teammate open/HMR → manage access → pause/resume → stop/expire → recover. | Verify final copy, accessibility, empty/error states and known-limit guidance against actual behavior; record unresolved supported-matrix gaps. | Publish acceptance record, operator runbook, limit/compatibility matrix and artifact/version manifest; define operational ownership and measurable pilot indicators. | Local qualification is complete and reviewable, with no unresolved P0 issue. Commit/push/PR/release/deployment are separate actions when requested; this planning epic does not perform them. Depends BM-10a/b. |

## Lifecycle and action contract

Persist lifecycle, revision, serving generation, creator authority reference and server expiry. Derive connectivity from bounded evidence. UI may show Live only when the lifecycle is active, authority is current and both connector and selected app are ready.

| Trigger or action | Lifecycle and availability | URL and expiry | Access effect |
| --- | --- | --- | --- |
| Create | Starting until end-to-end readiness; bounded startup deadline | Reserve one new host; set server expiry at creation | No content while readiness/authority is unproven |
| Ready | Active and online | Existing URL and expiry | Admit only current authorized reviewers |
| Pause | Paused | Same URL and expiry | Deny new content and terminate existing streams |
| Resume | Active only after fresh authority/generation/readiness | Same URL; no expiry reset | Reviewers authenticate under current grants |
| Local app stops | Active lifecycle, origin unavailable | Same URL and expiry | No successful app serving; recover only the same target |
| Network drop or sleep | Active lifecycle, reconnecting/offline | Same URL and expiry | Existing streams end; reconnect cannot extend authority |
| Extend | Nonterminal share only, inside policy ceiling | Same URL; explicit validated expiry update | Current authorization is still required |
| Remove reviewer grant | Share remains eligible for other reviewers | Same URL and expiry | Close sessions for users who no longer have any valid grant |
| Stop | Stopped, terminal | Old URL never targets a new share | Deny, close streams, invalidate connector, retain history |
| Expiry | Expired, terminal | Old URL remains terminal | Admission/lease deadlines enforce expiry before cleanup |
| Creator logout/auth expiry or permission loss | Revoked, terminal | A new share requires new authority and URL | End that publisher's shares and their reviewer streams |
| Org/feature/domain withdrawal | Revoked, terminal for affected shares | No silent migration of old links | Deny and drain within the lease bound |
| Graceful full app quit | Attempt Stop; force connector offline if CP cannot be reached | Stop is terminal; an unconfirmed stop leaves server state to authority/expiry reconciliation | No serving connector after quit; never pretend remote stop succeeded |
| App crash/proxy restart | Offline; server reconciles lifecycle | No automatic resurrection; explicit eligible recovery | Stale generations and credentials never serve |

## Proposed backend contract

Names below are design candidates, not existing endpoints. BM-0 and each implementing story finalize OpenAPI without assuming browser launch APIs can authenticate a desktop publisher.

| Resource or operation | Responsibility | Main stories |
| --- | --- | --- |
| Installation Beam domain/readiness | Shared serving base, revision, operator authority, DNS/TLS/capability checks | BM-1 |
| Organization Beam policy | Enabled state, publisher permission/groups, allowed audience, TTL/quota/MFA constraints | BM-1 |
| Beam share | Tenant, owner, connector identity reference, fixed target revision, host, expiry, lifecycle and versions | BM-2/3/6/7 |
| Create/list/get own shares | Idempotent create and safe owner projection; no connector secrets in general read APIs | BM-2/6 |
| List shared with me | Current reviewer grant and safe app metadata | BM-4 |
| Grant add/remove | Delegated, bounded, revisioned audience management | BM-2/6/7 |
| Pause/resume/stop/extend | Expected-revision state transitions and independent authority checks | BM-6/7 |
| Publishing bootstrap/connect/renew | Scoped authenticated desktop intent; proof of possession; exclusive serving generation | BM-3/7/8 |
| Reviewer launch/session/lease | Human browser parent, optional MFA, exact host, current grants, bounded streams | BM-4/7 |
| Typed events/health | Audit/access evidence, redacted diagnostics and capacity measurements | BM-9 |

Creation, grant decisions, transitions and their audit records must commit atomically. Routing and serving credentials are derived from current committed authority. Sweeper progress, UI state and process-local push are not authorization sources.

## Delivery sequence and demonstrations

| Milestone | Stories and slices | Concrete demonstration | Exit gate |
| --- | --- | --- | --- |
| M0 Contract and feasibility | BM-0a/b | Installed spike shares one loopback app to an authorized browser; HMR and revoked lease tested | Transport/runtime, domain topology, publishing authority and numeric limits decided |
| M1 Setup and private pilot | BM-1, BM-2, BM-3, BM-4; audit and limit primitives from BM-9 | Operator configures once; delegated developer creates; allowed teammate opens; another member is denied | Isolation, bootstrap, readiness and baseline fail-closed tests pass; feature remains opt-in |
| M2 Complete review workflow | BM-5, BM-6 | Actual local edit appears in reviewer browser; owner manages audience and pause/resume/extension | HTTP/HMR limits and owner management contract pass |
| M3 Withdrawal and recovery | BM-7, BM-8; complete BM-9 | Open streams stop on revoke/expiry; network/app recovery keeps URL and TTL; tray/quit behavior is truthful | Full withdrawal/outage matrix, bounded capacity and safe operational evidence pass |
| M4 Release qualification | BM-10 | Packaged desktop, configured proxy and full customer walkthrough | Exact-version evidence, install/upgrade/restore/rollback and product review complete |

Backend/core and desktop work may run in parallel after the contract is locked. Each milestone is demonstrated on the actual integrated stack before work advances. No time estimates are asserted until BM-0 resolves transport/runtime uncertainty and staffing is known.

## Definition of done for every slice

| Area | Required evidence |
| --- | --- |
| UI | Render the actual changed states, including denied/error/stale/empty; keyboard access and focus recovery; no layout-wide overflow. |
| Frontend | Typed bridge/API contracts, subscriptions cleaned up, stale responses ignored, operation context pinned, secrets absent from renderer; relevant meaningful tests and changed-package checks. |
| Backend and connector | Tenant/RBAC/authority enforced server-side; races/replay/idempotency/failure boundaries tested; cancellation and quota release verified; real migrations/contracts kept compatible. |
| Behavior | Slice acceptance passes through the actual involved layers. A hidden button or green unit test alone does not prove denial/termination/transport behavior. |
| Audit | Mutation/access events emitted under the agreed contract; secrets and request/response content excluded. |
| Preservation | Existing VPN, App Access and Shield contracts unchanged unless an explicitly reviewed shared-contract change is necessary. Owned test fixtures isolated from shared/customer data. |
| Record | Evidence identifies core/client source revisions, artifacts, supported platform/browser/topology and known limits. |

Use the repositories' existing generators and gates, including core generated-contract drift checks and full web typecheck/test/build for changed web scope. Run affected API/proxy/transport and desktop tests with real disposable integration services where needed. BM-10 consolidates final evidence after these checks already passed within their slices.

## Qualification matrix

| Category | Required cases |
| --- | --- |
| Identity | Publisher signed out/expired/revoked; reviewer local/SSO/MFA; unknown assurance; machine/agent/bearer reviewer denied; server/account/org switching races |
| Tenant and ownership | Foreign share/user/group/connector IDs; creator versus admin management versus reviewer content access; overlapping grants; safe directory and event projections |
| Transport | Wrong key/audience/generation; bootstrap/launch replay; loopback family/port bounds; LAN/metadata/absolute-URL/CONNECT abuse; untrusted local HTTPS; duplicate connectors |
| Browser content | Host-only cookies; rejected unsafe cookie domains; CP/cross-share CSRF and service-worker/framing behavior; credential stripping; safe redirects and relative return paths |
| Application | Root assets/forms/app auth/upload/download; configured external base URL; Vite HMR; SSE; WebSocket; documented unsupported redirects/hosts/apps |
| Withdrawal | Pause, Stop, share TTL, reviewer logout/login expiry/MFA/grant/group/member loss, publisher logout/auth/role/group/member loss, organization disable, entitlement/domain withdrawal |
| Protocol withdrawal | Fresh request, long HTTP upload/download, SSE and WebSocket for every applicable withdrawal; notification deliberately dropped |
| Outages and recovery | CP/session-store/proxy/connector crash; network drop; sleep/wake; local app restart; tray/window/full quit; restart/restore with stale credentials |
| Capacity | Concurrent creates, per-share and per-tenant limits, startup quota leak, oversized bodies/frames, slow consumers, disconnect storms and bounded buffers |
| Delivery | Core/client contract skew; packaged macOS/Windows app; fresh install; disabled-by-default upgrade; certificate expiry/rotation; disable/drain; backup/restore/rollback |

## Follow-up backlog

| Follow-up | Customer value | Reason for separate scope |
| --- | --- | --- |
| Optional CLI using the same connector contract | Headless developer workflows | Independent CLI auth, distribution and lifecycle qualification |
| CI-created previews | Review branch builds | Workload identity, build lifecycle and unattended authority |
| External reviewer invitations | Customer/vendor review | Guest sponsor, identity, expiry, invitation abuse and organization-boundary policies |
| Friendly custom hostnames | Memorable demo URLs | Collision, rename, domain ownership and cookie/history isolation |
| Comments or review annotations | Capture feedback in context | App-content/extension integration and collaboration retention |
| Multiple local services or paths | Frontend plus API demos | Routing, CORS/cookie boundaries and per-target authority |
| Automated DNS and certificate provisioning | Easier operator setup | Provider credentials, ownership challenges and certificate lifecycle |
| Proxy HA or connector handoff | Higher availability | Distributed route ownership and multi-instance authority qualification |
| Internet/LAN origins and generic TCP | Broader publishing | A different trust boundary; requires a separately scoped product contract |

## Implementation starting point

Start with BM-0a, then BM-0b. Confirm the current latest code in both repositories before coding, preserve existing working trees, and keep desktop changes in `tunnex-client`. The first reviewable implementation result is the agreed contract plus the packaged native transport spike, not a dashboard populated only with mock shares.
