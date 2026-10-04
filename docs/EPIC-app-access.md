# App Access epic and story plan

Status: **11/11 stories accepted within their recorded scopes**. The original nine stories (AA-0 through AA-8) remain locally accepted; per-app MFA is **Story 10 (AA-9), accepted and deployed to the isolated test CP on 2026-10-04, with 2/2 original slices accepted**. **Story 11 (AA-10 Company catalog, App admin and access requests) is accepted and deployed to the same isolated test CP**, including owned-fixture browser acceptance and preservation-verified cleanup. See the separate AA-9 and AA-10 acceptance records below.
AA-6a/AA-6b accepted slices: **2/2**. Actual publish/day-two administration, all15 five-protocol withdrawal cases, capacity, certificate expiry and isolated restore/install/upgrade/rollback pass. Fresh rendered local and SSO login reach the published origin, assets and form; exact own-session revoke and member admin denial pass. Temporary SSO configuration is restored exactly with one scoped audit, and the proxy is back on its original console/artifact/trust baseline. Local signing uses the documented ephemeral test key/image adapter; protected production signing and registry distribution remain separately requested release gates. Chrome desktop/390px is the rendered browser qualification scope, not a universal-browser claim. See [AA-8 evidence](AA-8-development-evidence.md).
Development contract: [AA-0 authority](AA-0-authority-contract.md).
Local evidence and ownership: [AA-0 evidence](AA-0-development-evidence.md).
Prepared 2026-10-03 against main `bcf602770c54446b35a2f83bfa639e9f2a9a10c8`.
Story namespace: **AA**. The original first release contains nine stories (AA-0 through AA-8).
The additional MFA story (AA-9), originally deferred, is now accepted as the tenth story.
The subsequently requested Company catalog, assigned App admin and access-request workflow is
**AA-10, the eleventh story**, and is **accepted on the isolated test CP**. The two
accepted MFA slices retain their original numbering and acceptance.
The original release boundary is preserved; the scoped acceptance records below do not
authorize deployment to other customer infrastructure.

## Customer outcome and agreed scope

A customer publishes a private web application through Tunnex. A contractor or
employee signs in using the customer's existing Tunnex authentication and opens
only an application explicitly granted to them. The user's computer needs a
browser; no Tunnex client, VPN connection, local agent or CLI is required.

The public feature name and standalone sidebar label are **App Access**.
Its description is **Open private web apps in your browser**.
The initial scope is HTTP/HTTPS web applications. Admins get Applications and
Access views. Members get My Applications. This feature is not nested inside
Access Policies or Resources.

Both **local email/password login and configured SSO** are first-release
requirements. A contractor can be invited as a local user when no SSO is configured.
Existing login verification, password-change, membership and configured MFA gates
still apply. The original v1 scope did not introduce per-app MFA. The subsequently
accepted AA-9 adds an optional app requirement using the user's existing factor or
verified SSO assurance, without a separate factor enrollment for every app. SSO login
alone does not prove MFA; see the accepted assurance contract below.

AI gateway, AI agents, MCP and the colleague's in-development AI sandbox are outside
this epic. Existing audit and access-event surfaces are reused with new event
producers; they are not proposed as new standalone products.

## First-release boundaries and proposed defaults

| Concern | First-release decision or planning default |
| --- | --- |
| Applications | HTTP/HTTPS origins, one configured origin and one selected enrolled gateway connector per app. Apps must support their published external URL. |
| Transport | A dedicated public app proxy receives browser traffic. The selected gateway makes an authenticated outbound data connection to that proxy and reaches the private origin. AA-0 proves/selects the transport implementation before product code depends on it. |
| Authentication | Reuse Tunnex local/SSO login. Application-scoped browser sessions are new. A backend app's own login remains unless that app has a separately supported SSO integration. |
| Authorization | Dedicated app grants over existing organization users/groups. Default deny, allow-only active grants, no implicit Everyone or admin-content access. Network Zero Trust mode does not turn app authorization off. |
| Commercial gate | Dedicated runtime `app_access` entitlement plus organization opt-in, default off. AA-0 records the tier mapping; existing groups are Community capabilities on this baseline. Do not promise a new SKU or alter group availability. |
| Domains | One controlled app base domain per installation; exact app hostnames unique across tenants. Prefer a separate registrable domain from the control plane to isolate untrusted app content. Sibling-domain support requires explicit cookie/CSRF proof in AA-0, not an assumption. |
| Certificates | Use existing supported edge certificate lifecycle where qualified. Proposed first path: explicit approved app hostnames and per-host certificates, or operator-provided certificates. No unrestricted on-demand issuance for arbitrary Host headers. |
| Session limits | Proposed default: 8-hour maximum and 30-minute idle expiry, always capped by the parent login's remaining lifetime and current authorization. AA-0 validates these as configuration defaults. |
| Revocation | No positive authorization cache for new requests in v1. Active streams use a renewable lease with a proposed maximum 5-second stale-authority window. CP/Redis unavailable means no new access; streams close when their lease ends. The bound is a release acceptance target, not an existing guarantee. |
| Availability | One app-proxy replica and one connector assignment per app in the first supported topology. No automatic gateway failover, transparent stream migration or multi-proxy HA claim. |
| Compatibility | Root-path application publishing; GET/HEAD, forms, uploads/downloads, redirects, cookies, SSE and WebSockets within explicit limits. No arbitrary HTML/JavaScript rewriting. |
| Out of scope | CLI/API-token use by end users, SSH/RDP/VNC, generic TCP/CONNECT tunnels, path-based multi-app hosting, wildcard origins, upstream password injection, universal app SSO, device-attestation equivalence, session video/content recording. |

No infrastructure provisioning is implicit. Customers supply a suitable app domain,
edge reachability, origin network path and origin-side firewall restrictions.

## Verified reuse and genuinely new work

| Existing source | Reuse | New work or limitation |
| --- | --- | --- |
| [AppShell](../apps/web/src/components/AppShell.tsx), [App routes](../apps/web/src/App.tsx) | Responsive navigation, authenticated org workspace and safe local login returns | Standalone App Access routes, admin/member views and safe cross-origin app return |
| [Session auth](../apps/api/internal/http/session.go), [Redis sessions](../apps/api/internal/session/session.go) | Active-user checks, membership lookup, local/SSO identity, idle/absolute expiry and logout | App-scoped cookies, launch-code handoff, parent-session binding and active-stream revocation |
| [RBAC](../apps/api/internal/rbac/rbac.go), [policy service](../apps/api/internal/policy/service.go) | Users, memberships, groups, named permissions, audit conventions | New app permissions/grants. Preserve existing group availability and enforce a separate App Access entitlement |
| [Policy compiler](../apps/api/internal/policy/compiler.go) | Identity relationships and established tenant-scoping patterns | Existing rules compile to VPN addresses; they do not authorize browser app sessions |
| [Gateway channel](../apps/api/internal/http/agentchannel.go), [node client](../apps/node/internal/control/client.go) | Gateway enrollment, certificate identity, capability/config/status conventions | Outbound browser data transport and app-origin connector; the existing control channel is not that transport |
| [nodepush](../apps/api/internal/nodepush/hub.go) | Fast notification as an optimization | Process-local notifications are not durable authority or sufficient revocation proof |
| [Audit Log](../apps/web/src/pages/AuditLog.tsx), [Access Events](../apps/web/src/pages/AccessEvents.tsx) | Existing operator views and retention/RBAC patterns | Browser authorization/session events and app filters; network-flow records cannot substitute |
| [nginx](../deploy/nginx/nginx.conf), deployment installers and Helm | Existing public edge, release/configuration conventions | App-host routing, certificates, dedicated proxy service, connector capability and upgrade/rollback |
| [Screen census](../apps/web/test/screencensus.test.ts) | Required screen wiring and failure-state coverage | Every new page and role-specific journey needs entries and actual browser evidence |

The AI reverse proxies are examples of narrow proxy handling, not components to
repurpose or change in the colleague's scope.

## Product UI and journeys

### Navigation and roles

    ACCESS
      App Access
      Access Policies
      Devices
      Users & Groups

| Persona | Landing and visible actions | Data boundary |
| --- | --- | --- |
| App administrator | Applications and Access tabs; add/manage/publish/disable apps; manage grants within named permissions | May inspect configuration without automatically receiving app-content access |
| Ordinary member or contractor | My Applications; search, description, optional bundled icon, Open | Only currently authorized apps; no origin addresses, gateway metadata or other users' grants |
| Administrator using an app | My Applications action alongside management | Same explicit content grant as an ordinary member |
| Member without apps | Clear No applications assigned state | Distinct from load error, auth failure or feature unavailable |

Proposed routes are /app-access, /app-access/applications,
/app-access/applications/new, /app-access/applications/:appId,
/app-access/access and /app-access/my-applications. The root selects the permitted
landing. Hiding navigation never replaces backend authorization.

### Admin flow

1. **Create draft:** name, description, origin URL, selected connector, proposed browser hostname,
   and app-wide idle/absolute session limits within supported bounds.
   V1 icons come from a bundled set; remote image fetching is not required.
2. **Check connection:** separately show connector eligibility, origin DNS/connectivity/TLS,
   published hostname resolution and certificate readiness, with timestamps and exact blockers.
3. **Assign access:** existing users/groups and a validity window for each grant.
   Session limits are app-wide application settings, not properties of overlapping grants.
   The original first-release UI had no per-app MFA switch; the accepted AA-9 extension adds an optional app requirement.
4. **Review and publish:** show URL, audience, expiry and the exact configuration revision.
   Server validates the reviewed revision. Successful save is not successful publication.
5. **Operate:** staged edits preserve the active revision until the new revision is validated/applied.
   Sensitive changes require revalidation; disabling access takes effect independently of origin health.
6. **Disable/revoke/delete:** show server-derived affected access/session count where available.
   Preserve a truthful pending/confirmed state for termination and retain audit evidence.
   Disabled apps can be deleted only after live routing is withdrawn under the defined contract.

Use a full page for the wizard. Use small modals for individual grants or confirmations.
Keep Applications details and global Access views backed by the same grant records.
Do not require administrators to visit the VPN Rules screen to configure this feature.

### User flow

Catalog Open and a direct app URL converge on one authentication/authorization flow.
After local login or SSO, return to the exact registered app and validated relative path.
Keep multiple organizations and multiple app tabs isolated. Expired login requires sign-in;
expired/removed app permission denies access. Never automatically replay a POST/form submission
after reauthentication. An already delivered page cannot be recalled after revocation.

My Applications includes a compact **My sessions** action. Show only the member's own app
sessions, label the current session, and allow scoped sign-out/revocation of selected app
sessions without signing out other users. Explain the difference between ending an app
session and logging out of Tunnex; parent-login logout ends its bound app sessions.

Distinguish empty, loading, inaccessible, unavailable and session-expired states.
Unauthorized direct links must not reveal private topology or other tenants' application existence.
Existing app login screens can still appear; do not promise automatic login to arbitrary origins.

## Architecture and authority

    Browser --HTTPS--> public app proxy --authenticated outbound channel--> gateway connector
                             |                                               |
                             | authorize/session                             | exact registered origin
                             v                                               v
                         Tunnex API <--> PostgreSQL / Redis             private HTTP/HTTPS app

The control plane owns identities, app intent, grants, sessions and policy decisions.
A dedicated app-proxy data plane terminates app browser sessions and forwards approved traffic.
A connector component on an enrolled gateway reaches the registered origin. Application bodies
do not run through the ordinary control-plane API or its Tunnex-specific CSRF middleware.

Candidate new modules: apps/api/internal/appaccess for control services,
apps/node/internal/appaccess for connector/reconciliation, and a separately deployable Go
app-proxy module/service. AA-0 finalizes the module boundary and maintained transport dependency.
Do not create a custom cryptographic protocol or silently fall back to public origin exposure.

Each data connection authenticates a gateway certificate and organization. Each stream is bound
to the application, assigned gateway and serving revision. The browser never supplies a dial target.
The connector accepts exact configured origins only; it is not a general proxy.

## Data and API plan

Names below are proposed contracts. Allocate migration numbers from latest main at implementation
time; do not reserve today's next migration while AI work is proceeding independently.

| Store | Proposed fields and responsibilities | Owning story |
| --- | --- | --- |
| Organization feature configuration | App-access opt-in, entitlement-derived availability; installation domain stays operator-scoped | AA-1 |
| App/domain registry | Org/app IDs, normalized unique public hostname, name, description, assignment, draft/active revision and lifecycle | AA-1 |
| App revisions | Exact scheme/host/port, TLS server name/private CA reference, permitted destination constraints, session settings, immutable reviewed configuration digest | AA-1 |
| App grants | Org/app, subject user or group, validity window, enabled/version and actor; tenant-safe foreign keys and deterministic allow-only union | AA-2 |
| Runtime application status | Desired/applied revision, gateway capability, connector health, individual checks and observed times; bounded history | AA-3/AA-6 |
| Launch transactions in Redis | Hashed opaque single-use code, app/host/org/user/parent-session binding, browser nonce, short TTL, atomic redemption | AA-5 |
| App sessions in Redis | Opaque token hash, app audience, user/org, parent-login reference, absolute/idle limits and revocation indexes | AA-5 |
| Audit and access records | Existing audit storage for changes; typed browser decision/session producer with app and correlation fields, indexes and retention contract | AA-7 |
| Authentication assurance | Server-verified factor/issuer assurance and timestamp on the existing parent session; fixed 15-minute app freshness | AA-9, accepted |
| Company discovery and scoped administration | Per-app default-hidden catalog visibility, one active same-organization App admin assignment, retained request/decision history and versioned decisions using existing grants; safe member/owner projections | AA-10 (Story 11), accepted on the isolated test CP |

| API family | Proposed operations | Security boundary |
| --- | --- | --- |
| Organization /app-access/applications | List/create/get/edit draft, revision read, check, publish, disable and delete | Named read/manage permissions, tenant membership, optimistic concurrency |
| Organization /app-access/grants | List/create/update/revoke; effective-access preview | Separate grant permission; same-org app and subject; current validity evaluated server-side |
| Organization /app-access/my-applications | Current user's authorized app projection | Session user is authoritative; no arbitrary user-ID enumeration |
| App launch and redemption | Auth redirect, issue/redeem launch transaction, app cookie issuance | Registered exact host/path, browser binding, CSRF/login-CSRF protection, no open redirect |
| Internal proxy authorization | New-request decision and bounded active-stream lease renewal | Dedicated proxy service identity; app/user/session/host/revision binding; not publicly callable |
| Gateway app channel | Desired configuration, applied status, bounded connectivity check and data-channel authorization | Existing enrolled gateway identity plus explicit app capability/assignment |
| App session lifecycle | List own sessions, permitted admin session view/revoke, logout propagation | Own-user projection or named privileged permission; scoped session index |
| Browser access events | Filtered producer/query contract integrated into Access Events | Typed event family; independent of VPN zero-trust-mode visibility |

Follow OpenAPI-first generation for API, CLI/shared types as applicable; no hand-maintained
client contracts. No tunnex-client repository change is expected for browser-only delivery.
Do not add desktop-client code to this repository.

## Story summary

Complexity is relative, not a delivery-date commitment. AA-0 must re-estimate transport and
compatibility work before a calendar schedule is promised. AA-0 is **Locally complete**;
AA-1 is **Locally complete** ([acceptance evidence](AA-1-development-evidence.md));
AA-2 is **Locally complete** ([acceptance evidence](AA-2-development-evidence.md));
AA-3 is **Locally complete** ([acceptance evidence](AA-3-development-evidence.md));
AA-4 is **Locally complete** ([acceptance evidence](AA-4-development-evidence.md));
AA-5 through AA-8 are **Locally accepted**, as recorded in the first-release evidence above; protected production signing and registry distribution remain separate release gates. AA-9 is **Accepted and deployed to the isolated test CP**, with both original slices accepted; its evidence and live SSO limitation are recorded below. AA-10 is **Accepted and deployed to the isolated test CP**; backend and web gates, actual admin/member/App admin browser flows, responsive review and owned-fixture cleanup with preservation proof are complete.

| Story | Customer or engineering outcome | Size | Depends on |
| --- | --- | --- | --- |
| AA-0 Architecture and contracts | Prove the selected topology and freeze truthful UX/security/compatibility contracts | L | None |
| AA-1 Application registry | Tenant-safe drafts, revisions, permissions and basic admin inventory | M | AA-0 |
| AA-2 App permissions | User/group grants, expiry and effective-access decisions | M | AA-1 |
| AA-3 Gateway connector | Authenticated outbound app channel and exact-origin connectivity | L | AA-0, AA-1 |
| AA-4 Browser data proxy | Host-isolated public proxy with qualified web protocols | L | AA-3 |
| AA-5 Login and My Applications | Local/SSO launch, isolated app sessions, end-user portal | L | AA-2, AA-4 |
| AA-6 Publish and admin experience | Guided setup, reliable readiness, staged publish and recovery UX | M | AA-1–5 |
| AA-7 Withdrawal and operations | Bounded revoke/expiry, logs, health, packaging and upgrades | L | AA-3–6 |
| AA-8 Integrated qualification | Real admin/contractor acceptance, compatibility, failure and release proof | L | AA-0–7 |
| AA-9 Per-app MFA step-up — accepted | Optional sensitive-app reauthentication with verified assurance; both original slices accepted on the isolated test CP | M/L | AA-8 |
| AA-10 Company catalog, App admin and access requests — accepted (Story 11) | Opt-in same-organization discovery, one scoped App admin, grant lifecycle, retained in-app request history, role-aware navigation and qualified day-two controls | M/L | AA-2, AA-5, AA-9 |

## Detailed story and slice table

Each slice includes implementation-level tests; AA-8 does not defer earlier security validation.
“UI: none” means no customer screen work, not permission to invent a placeholder screen.

| Story and slice | Backend and data changes | UI work | Gateway and deployment work | Exit proof and dependency |
| --- | --- | --- | --- | --- |
| **AA-0a Product and authority contract** | Specify RBAC/entitlement matrix, allow semantics, domain isolation, session authority, expiry/revoke behavior, limits and API sketches. Document local/SSO parity; defer app MFA. | Admin/member wireframes, setup states, empty/error states and proposed wording. | Record single-proxy/single-connector topology, TLS/DNS prerequisites and origin restrictions. | One reviewed contract with measurable revoke limit and no hidden app-login or universal-compatibility promise. |
| **AA-0b Transport and compatibility spike** | Define proxy identity, channel/stream binding, backpressure and bounded resource contract; select maintained library after license/security fit check. | No production UI; use the proposed flow to assess operational complexity. | Isolated origin plus outbound connector prototype: HTTP, SSE, WebSocket, cancellation, reconnect and slow reader. | Instrumented origin proves approved bytes traverse the selected path; forged app/org streams denied. Record fit decision and revised estimates. Prototype is not shipping completion. |
| **AA-1a Registry and permissions** | Add tenant-scoped registry/revisions/feature setting; CRUD, uniqueness, gateway ownership, optimistic versioning, audit transactions; named app read/manage/grant/use permissions and generated RBAC mirror. | Shared types only. | Configuration schema and capability version contract, no traffic yet. | Cross-tenant/foreign gateway/duplicate-host/stale-edit tests; historical DB compatibility and safe down-migration behavior. Depends AA-0. |
| **AA-1b Draft inventory** | List/detail projections and safe pagination/filtering; structured validation errors. | Standalone App Access navigation, Applications list, draft create/details, authorization-aware controls, unsaved-input recovery. | Show gateway eligibility from actual capability. | Admin/member route isolation, no granted-content assumption for admins; rendered loading/error/empty/draft states and screen-census entries. |
| **AA-2a Grant evaluator** | User/group grants, validity, revisions, effective-access preview; active user/membership/app/feature checks. Reuse identity tables, not VPN-IP expansion. Define group-deletion/deprovision hooks. | Typed subject picker/API contracts. | No data-plane allow until evaluator is wired. | Default deny, overlapping grants, expiry at request time, removed group/user membership, foreign subject and feature-off tests. Depends AA-1. |
| **AA-2b Access management** | One grant store powers app-local and global views; permission-scoped impact/revoke endpoints. | Access tab, user/group selectors, validity fields, app-local access editor and confirmation states; links to existing directory. | No new gateway permission UI. | One edit reflected in both views; no implicit Everyone grant; stale-save and failure recovery; member cannot query global grants. |
| **AA-3a Connector identity and desired state** | Purpose-scoped gateway app authorization, app assignments, desired/applied revisions, capability and status endpoints. | Connector suitability/status projections for wizard. | App connector component, outbound mutually authenticated channel, enrollment/rotation/revoke compatibility, exact app/revision stream binding. | Wrong certificate/org/gateway/revision refusal; certificate rotation, old runtime compatibility and reconnect proof. Depends AA-0/1. |
| **AA-3b Origin access and checks** | Bounded check requests/results with request ID, configuration digest, timestamps and redacted errors; rate limits. | Show distinct DNS/connect/TLS check results without calling them end-user authorization. | Resolve/dial at gateway; validate current addresses and origin TLS; allow explicit private networks but refuse metadata/control/loopback/reserved targets by default. No redirects during probes. | DNS rebinding, IPv4/IPv6 aliases, changed resolution, forbidden target, timeout, private CA and wrong-network checks. |
| **AA-4a Public routing and proxy** | Internal app route lookup and machine-authenticated authorization client; unknown hosts denied. | Safe generic error pages, no private origin disclosure. | New isolated app-proxy service; edge route only approved app hosts; trusted forwarded headers, strict parser, no CONNECT; origin routing over connector. | Spoofed Host/identity headers, request smuggling defenses, foreign tenant host, CP-route interception, credential/cookie leakage tests. Depends AA-3. |
| **AA-4b Browser compatibility** | Define request/session decision and protocol-upgrade hooks. | Meaningful unsupported-app and connection-interrupted messages. | Qualified redirects/cookie rewriting only for configured origin; configured external URLs; forms, SPA assets, bounded uploads/downloads, SSE, WebSockets, cancellation/backpressure. | Real fixtures for each supported behavior; origin TLS verification; browser same-origin/CORS/CSRF boundaries; no blanket content rewriting. |
| **AA-5a Login handoff and app sessions** | Reuse local/SSO login and configured gates. Add short-lived browser-bound single-use launch code, atomic redemption, app/host/org/user/parent session binding, separate cookie namespace and expiry. | Login return and app session-expired flows; never replay POSTs. | Proxy redemption/auth/session strip rules; parent CP cookie and internal credentials never reach origin. | Local user without SSO, SSO user, configured login MFA, login-CSRF, code replay, open redirect, parent logout and cookie-isolation proof. Depends AA-2/4. |
| **AA-5b My Applications portal** | Own-user authorized app listing, launch and own-session list/revoke endpoints; no admin content bypass. | Member My Applications, search/cards/Open, compact My sessions with current/other-session labels and scoped sign-out; admin My Applications action, deep-link return, mobile/keyboard flows and useful no-access states. | No browser-installed component. | Fresh browser without VPN opens only granted app; denied direct URLs, org switching, stale responses, multiple tabs, own-session revocation and user privacy tests. |
| **AA-6a Review and publish** | Server-side preflight/check freshness, validated revision digest, staged publication, idempotent operation/readback and reconciliation status. Refuse changed review or invalid prerequisites. | Four-step Add application page: Application, Connection, Access, Review & publish; save draft, resumable errors, exact access summary. | DNS/TLS/connector serving readiness; new revision becomes active only under the agreed atomic publication contract. | Saved does not imply published; stale/failed check and partial apply do not open access; active revision survives failed staged edit. Depends AA-1–5. |
| **AA-6b Day-two administration** | Edit, disable, re-enable, rollback-to-validated-revision and safe-delete contracts; bounded impact projection. | Application details, independent publication/health states, action confirmations, retry/reconcile unknown outcomes and filtered event links. | Origin/cert/connector faults correctly attributed; disable routing independent of origin reachability. | No duplicate consequential operation after timeout; no app-host reassignment while old route/session remains usable; deletion preserves audit. |
| **AA-7a Revocation and outage handling** | Session indexes by app/user/parent, per-request current decisions and expiring active-stream leases. Cover grant/user/group/logout/app/gateway/license changes. Authoritative state wins over notifications. | Requested versus confirmed termination status; administrator session revoke with exact scope. | Close active streams within the qualified bound, including long HTTP responses and uploads/downloads; lost push, process restart and CP/Redis failure fail closed. | Every revoke trigger tested with fresh requests, already-open SSE/WebSockets and long HTTP transfers; dropped notification still meets bound. Termination cannot erase delivered content or undo a mutation already accepted by the origin. Depends AA-3–6. |
| **AA-7b Events and operations** | Atomic config/grant audits; typed app decisions/session events with safe metadata, independent app-event permissions, bounded buffering/retention and metrics. | Extend existing Audit Log/Access Events filters; app-focused health view and useful repair guidance. | Redacted logs; health/capacity metrics for streams, connector failures, origin latency and buffer saturation. | No cookies/tokens/bodies/query secrets in logs; app events visible under proper permission even if VPN Zero Trust is off; multi-tenant and retention tests. |
| **AA-7c Packaging and upgrades** | Configuration validation, feature/capability compatibility and rollback checks. | Domain/TLS prerequisite instructions and incompatible-runtime explanations. | Signed app-proxy artifact, Compose/Helm/installer wiring, limits, edge listener, cert renewal, monitoring, backup/restore and disable/uninstall runbook. | Fresh install, disabled-by-default upgrade, restart persistence, origin bypass restriction and restore/rollback proof; existing VPN/AI services unchanged. |
| **AA-8a Security and compatibility qualification** | Full relevant API suites with real isolated PostgreSQL/Redis in both editions; generation/contract/migration checks. | Real rendered admin/member flows; all new screens in census; responsive/accessibility contract below; focused E2E plus full web gates. | Native qualified connector/proxy topology, supported browser matrix and public/private-origin fixtures. | Negative tests first; local and SSO login, allowed/denied app, known compatibility limits, tenant isolation and all revocation paths evidenced. Depends AA-0–7. |
| **AA-8b Release acceptance and handoff** | Document final capability/limits and operational ownership. | Founder/customer walkthrough of create→grant→publish→open→revoke→disable, including recovery states. | Load/slow-consumer bounds, cert expiry/renewal, origin/connector/CP outages, upgrade and rollback on supported topology. | Evidence tied to source/artifact; no HA/universal-app claim without proof. Release/deployment only when separately requested; no automatic CI watcher. |
| **AA-9a Authentication assurance — accepted** | Verified server-side MFA timestamp/source on the existing parent session; local TOTP/recovery and verified signed ID-token MFA assurance with original auth_time; fixed 15-minute freshness. Unknown, stale or future proof cannot satisfy the app requirement. | Optional app MFA control with confirmation, independent of the organization mandate; reuse account factors. | Schema 176 and API/web deployed to the isolated test CP; gateway/proxy unchanged. | Session/MFA and signed OIDC/callback suites passed; live account MFA reused for app access. External customer SSO was not live-tested. Originally outside the nine-story v1 scope; accepted 2026-10-04. |
| **AA-9b Step-up journey — accepted** | Authenticated, CSRF-protected same-parent step-up with rate limits, factor replay protection and atomic assurance promotion that preserves session lifetimes; runtime policy and freshness enforcement. | Setup through the existing account factor flow, recovery-code acknowledgement and safe return to the app; reuse fresh assurance without another challenge. | Existing unverified app sessions fail closed when the requirement is enabled; authority leases honor proof freshness. | Live admin OFF/ON, blocked existing session, setup-to-app, same-parent reuse, rejected wrong login code and successful MFA-login-to-app passed; isolated replay/expiry/logout/TTL tests passed. Depends AA-9a; accepted 2026-10-04. |
| **AA-10 Company catalog and access requests — accepted** | Default-hidden visibility; versioned single-owner assignment; safe projections; durable request history; atomic approval through existing grants; scoped grant lifecycle, administrator fallback and server-side grant filters. | My access/Company apps/My requests, scoped Manage access/Requests, role-aware navigation, Access grant table with scoped history links, and the organization App Access switch under Settings → Features; existing Open/MFA reused. | Schema 177 and final API/web deployed to the isolated test CP. Gateway/proxy and unrelated services preserved; no new cloud topology. | Real admin/member/App admin flows, grant/MFA separation, reassignment and fallback, retained history, 1440px/390px review and exact owned-fixture cleanup passed. All 24 protected durable data projections match the cleanup baseline. |

## Security and compatibility acceptance contract

Shared UI acceptance applies to both admin and member routes. At narrow widths, every
route/action remains reachable and long names/URLs do not cause page-wide overflow.
A keyboard user can complete setup, grant, launch and revoke; dialogs restore focus.
Statuses and errors have accessible names/announcements and do not rely on color.
Extend the existing [responsive contract](../apps/web/test/responsivecontract.test.tsx)
and screen census, and verify these outcomes in rendered browser journeys.

| Boundary | Required behavior and proof |
| --- | --- |
| Tenant and identity | User, membership, group, app, hostname, gateway and session belong to one authorized scope; cross-tenant identifiers disclose no private metadata. |
| Public app content | Never share the control-plane origin or forward its cookies. Use host-only Secure/HttpOnly app cookies with the __Host- prefix where applicable. Test cookie tossing, sibling origins, duplicate cookies and SameSite assumptions. |
| Authentication handoff | Code has short TTL, one redemption and browser/session/app audience binding. Callback consumes/redacts it before upstream traffic; no tokens in analytics/referrers/access logs. |
| CSRF | Control-plane API keeps its existing guard. App listener needs its own explicit Origin/Referer and cross-app request policy; preserve origin app protections. No arbitrary cross-origin credentialed allow policy. |
| Origin dialing | Registered scheme/host/port only; validate all resolution results at dial time and constrain reachable ranges. Private-origin access is allowed deliberately; metadata and control-plane services are not incidental targets. |
| Origin identity | Verify HTTPS hostname/chain using approved system/private CA trust; no global skip-verify switch. V1 does not inject a trusted-user header that an arbitrary app could accept without integration. |
| App behavior | A grant controls entry to the application, not its own read/write roles. Origin authorization and login remain the app's responsibility. |
| Session withdrawal | New requests reauthorize; old streams, including long HTTP responses/uploads/downloads, have bounded authority leases. Check membership/grant expiry without relying on a scheduled expiry job. No replay of failed uploads or mutations; termination cannot undo an operation already accepted by the origin. |
| Resource limits | Specify headers/body/stream/concurrency/buffer/time limits; exercise slow readers, cancellation and reconnect. Capacity estimates are measured on the named topology. |
| Device posture | A browser is not an enrolled healthy device. No fabricated disk/EDR posture. Unsupported device conditions are not silently treated as passed. |
| Data handling | Log identities, app, action/result, safe correlation and bytes/timing as needed. Never store app content, passwords, cookies, launch codes, full query strings or request bodies by default. |
| Compatibility claims | Name qualified app configurations/browsers. Path-prefix hosting, iframe cross-site behavior, hardcoded internal URLs and unusual cookie/OAuth flows require separate qualification or clear refusal. |

## Dependency order and implementation ownership

1. AA-0 establishes engineering feasibility and the contract.
2. AA-1 and AA-2 establish control-plane intent; AA-3 can proceed against the
   agreed registry/channel contract after AA-1a.
3. AA-4 follows the connector proof. AA-5 combines authorization with actual browser
   delivery. Admin draft/access UI can progress alongside those contracts.
4. AA-6 integrates publication/readback; AA-7 must finish before any beta claim.
5. AA-8 proves the original first-release customer journey; AA-9 followed as the separately accepted tenth story.
6. AA-10 is the separately requested eleventh story, accepted after backend gates, reviewed isolated test-CP deployment, owned admin/member/App admin browser acceptance and preservation-verified cleanup.

Recommended lanes after AA-0: control-plane/data model, connector/proxy, and web UX.
One integration owner maintains OpenAPI, state transitions and the compatibility matrix.
Shared-file changes are coordinated; do not delegate conflicting edits. Story sizes and
calendar estimates must be revisited after the transport spike.

## Verification and state-preservation rules

- Follow repository OpenAPI-first, SQL query scoping, generated RBAC and migration conventions.
  Verify latest migration numbering after concurrent main changes.
- Run tests appropriate to each changed layer. Use owned isolated PostgreSQL/Redis fixtures,
  preserve unrelated containers and record the precise environment.
- Historical schema tests must target their owned child database explicitly; never reuse an
  admin DSN accidentally retained by a copied pgx configuration.
- Existing users/groups and audit files are reuse targets; AI modules and the colleague's sandbox
  are outside the modification boundary.
- Preserve unrelated dirty/untracked files and stashes. Documentation publication is distinct
  from product implementation; no cloud mutation, restart, deployment or secret use is implied.
- No automatic GitHub PR/CI watching. CI checks may be read when requested for a specific task;
  publishing this plan is not a request to start a monitor.

## New development chat handoff

Start from latest main after this planning commit is published. Inspect Git state and active
worktrees, preserve unrelated work, fast-forward main, and create a new repository-convention
feature branch (proposed **feature/app-access**) if it does not already exist. Never overwrite
an existing same-named branch. If local changes prevent a safe switch, use an isolated checkout.

Read this epic and the linked source seams before implementation. The first bounded work item
is **AA-0**, not all stories at once. Record any changed baseline/assumption and qualify the
transport contract before implementing dependent product slices. Existing SSO/local login is
v1; per-app MFA was deferred to AA-9 in this original planning handoff. Its subsequent implementation and scoped acceptance are recorded below.

## Subsequent local UI quality pass — 2026-10-04

[UI quality evidence](AA-8-ui-quality-evidence.md) records the rendered workspace comparison, responsive and keyboard checks, lifecycle proof and final web gates. Current Payroll is active revision17/authority10; final web suite has1881passed plus2expected failures across152files. The preceding source/bundle hashes and authority9 readbacks are historical snapshots before this UI pass. No remote action is implied.

## AA-9 test-CP acceptance — 2026-10-04

Both original slices, **AA-9a Authentication assurance** and **AA-9b Step-up journey**,
are accepted. At this acceptance checkpoint, the epic had **10/10 stories accepted within their recorded scopes**. Story 11 (AA-10) was accepted subsequently; the current total is **11/11**, with its separate evidence below:
the original nine-story local release qualification is unchanged, and AA-9 was additionally
deployed and verified on the isolated App Access test CP at `https://internal.tunnex.app`.
This is test-CP acceptance, not a protected production release or approval to deploy elsewhere.

The authoritative acceptance record is
`/home/ubuntu/app-access-staging/per-app-mfa-20261004/per-app-mfa-acceptance.json`
(SHA256 `bb40b100cd977015c173abd5ef89cbee9d27fd1d8cf21ddaff7b600fd4c03a3b`).
Deployment verification is recorded in
`/opt/tunnex-app-access-live-updates/mfa176-ca0103a90d9cb7ca/runtime-order-attestation-1791107793528359643.json`:
schema 176, exact candidate binaries/assets, existing data and MFA factors preserved,
with gateway/proxy and unrelated services unchanged.

Live browser acceptance covered admin enable/disable confirmations, independence from
the organization MFA mandate, denial of an existing unverified app session after enable,
account-factor enrollment with recovery-code acknowledgement followed by app launch,
fresh same-parent reuse, rejected incorrect login MFA, and successful account MFA login
reused for app access. Session/MFA, App Access/HTTP/database and signed OIDC/callback
suites passed; web gates recorded 1975 passing tests and two existing expected failures,
plus passing typecheck and production build.

**SSO qualification limit:** signed OIDC fixtures were tested; an external customer SSO
provider was not live-tested. Only verified signed ID-token MFA assurance (`amr=mfa`)
with the original valid `auth_time` satisfies the fixed 15-minute freshness policy.
Ordinary SSO without that proof continues to work, and a protected app requires step-up.

This documentation-only status update follows the candidate source manifest
`e1be40854ca115798d4e1228d6bce43807c94edca63ee4e29b3d59f0459630c8`.
It does not change the tested or deployed binaries/assets; no rebuild is required for
this update. The pre-edit document is retained with the stage evidence.


## AA-10 / Story 11 — Company catalog, App admin and access requests

Status: **ACCEPTED AND DEPLOYED TO THE ISOLATED TEST CP** (2026-10-04). This is the
eleventh story, separate from accepted Story 10 per-app MFA (AA-9a/AA-9b, **2/2**).
Acceptance includes the actual browser workflow, final day-two controls and owned-fixture
cleanup with an independent preservation comparison.

### Required behavior

- Existing and new applications start **hidden from unauthorized members** in the
  Company apps catalog. A control-plane app administrator explicitly opts individual
  generic applications into same-organization discovery. Published, opted-in apps
  expose only safe display metadata, App admin identity/availability and the member's
  own request state; private origin, gateway and administrative configuration remain
  protected. Existing authorized My access entries remain available independently.
- The control-plane administrator appoints **one active same-organization App admin**
  before initially enabling catalog visibility. Here, control-plane administrator
  means the existing application management and grant authority
  (`app_access:manage` plus `app_access:grant`); the feature does not introduce a
  new installation-wide `cp_admin` requirement or give that flag to an App admin.
- An assigned App admin can manage user/group grant lifecycle and approve/reject
  requests **only for the currently assigned app**. Assignment grants no app content
  access, global directory/network administration, origin/gateway configuration,
  publication or MFA-policy powers. Safe app-scoped APIs and subject selection must
  work for an otherwise ordinary member without expanding global roles.
- If the assigned owner later becomes unavailable, inactive or unassigned, an already
  visible app can remain discoverable and accept new requests. Current and pending
  requests are retained. The control-plane administrator can review them or reassign
  the app; members see the unavailable-owner/fallback status.
- Members see **My access**, **Company apps** and their request history. An unauthorized
  member can request access and see pending, approved or rejected state. App admin
  identity appears on company-app cards and request status. Pending requests, queue
  badges and statuses are durable **in-app** notifications; this story sends no
  external email, Slack or other message.
- Approval and its grant effect are one versioned, atomic operation through the
  existing grant model. Reuse existing valid access where appropriate; reject stale
  reviewer decisions and do not recreate revoked grants through decision replay.
  Hiding or reassigning an app retains request history and existing grants.
  Historical approval alone never authorizes Open; a member whose access has since
  expired or been revoked can request again when the app remains discoverable.
- Authorized members retain **Open** and the already accepted MFA flow. A valid grant
  with stale/missing MFA proof shows Open plus the MFA requirement and proceeds to the
  existing challenge/setup journey. Request approval and App admin assignment never
  create MFA assurance or bypass account/app MFA policies. Existing app publication,
  grants, sessions and factors remain protected.
- Use the existing Tunnex navigation, tables, controls and confirmation/error patterns.
  Scoped App admin screens must not load full application configuration or global
  directory APIs merely to display grants or requests.

### Final acceptance evidence

Story 11 is accepted on the isolated test CP at `https://internal.tunnex.app`.
The authoritative record is
`/home/ubuntu/app-access-staging/company-apps-20261004/final-acceptance-20261004.json`,
SHA256 `f1812a8bce559919ee9308192cf450ca2aa8999823c07d8db508efa84029bd72`
(`ACCEPTED_ON_ISOLATED_TEST_CP`).

- **Backend:** original **82**, navigation **6** and grant-filter **14** top-level
  tests passed with zero skips in separate, overlapping qualification runs. These
  are not a summed unique-test total. The 377-operation authentication walk,
  generated CLI compilation, schema/query guards and isolated-parent preservation
  passed. Evidence: `backend-qualification.json`, `navigation-fix/qualification.json`
  and `grant-filters/qualification.json` under the stage above.
- **Web:** typecheck and production build passed; **159 files, 2022 passed and two
  existing expected failures (2024 cases)**. Grant tests were **20/20**. Evidence:
  `grants-table-ui-qualification.log` in the same stage.
- **Deployment:** `catalog-access177-04eff2abd6437a0a`, clean schema **177**.
  Source-manifest SHA256 `f27a76e2e1e4d5a3fa397fa70b552cb778d7f0650677a74271d01879039bbc57`;
  candidate manifest `04eff2abd6437a0a77fd6ff2da4b0c60b9a46ec3cfe1b0d168e12854abed802a`;
  installed web index `4c8e21888412af5b1f3ba1569fcf099e203dead9a167278529545c38ced2b66b`.
  Verification: `/opt/tunnex-app-access-live-updates/catalog-access177-04eff2abd6437a0a/verification.json`,
  SHA256 `5939e64207a97bcffbd25d435d816f535c1169c601eee7ab54dfb8dd8ec2cc04`.
- **Browser:** default-hidden discovery, opt-in/assignment, request/approval/rejection,
  retained history, reassignment and administrator fallback passed. Assigned App
  admins stayed scoped and received no implicit content access. Explicit grants
  opened the private Wiki; revocation removed Open while retaining history, and
  existing MFA enforcement remained effective. Real administrator/member/App admin
  navigation and **1440px/390px** views passed with no page-level horizontal overflow
  and independent screenshot review.
- **Day-two controls:** the Access grant table, combined server filters before
  pagination, owned-grant disable/edit restoration, revoke confirmation, exact grant
  Audit history and scoped Observe links passed. App Access OFF/ON each persisted
  across reload under **Settings → Features**; Applications retains only **Manage
  feature**, with no duplicate switch. Member access to Features was denied.
- **Owned cleanup:** fixture `a81cb8f5b8` was disabled, withdrawal confirmed and its
  app archived; no pending publication or unrevoked grant remained. Three owned
  users were deactivated and all **three request-history records** retained.
  Independently compared **24 protected durable data projections** matched exactly,
  including existing apps/publications/grants/users/MFA/domains. Comparison:
  `/home/ubuntu/app-access-staging/company-apps-20261004/cleanup-preservation/after-20261004T124358812404Z.json`,
  SHA256 `e4c6e31b46bd0b701f699c778278d92a8e94c1d2a50bb4f6b151d2e0aa261986`.
- **Test resources and final health:** the two isolated test containers, two anonymous
  volumes and exclusive network were removed by exact ownership checks; backups and
  logs remain. Owned browser sessions/tabs and the local temporary credential file
  were cleaned up. All seven live services retained expected image IDs and passed
  health/readiness checks. Evidence in the stage: `isolated-test-cleanup.json`
  (SHA256 `27b5147b432fd90ae376312287ebfac460e9cffb495171d18c4f14740c7f5cbe`) and
  `final-health.json` (SHA256 `121dfb31e32a1841d7ca39f647155cb2961d2e2d228cca4b6c5f121e03ef75aa`).

This documentation-only record follows the frozen runtime artifact. Runtime
access-event delivery retains its existing bounded/best-effort limits; no lossless
runtime-auditing claim is made. All **11/11 stories** are accepted within their
recorded scopes. Local synchronization, Git commit/push and broader release or
deployment remain separate actions.

## AA-10 stable navigation correction — 2026-10-04

Accepted on the same isolated test CP. Shared capability-aware navigation keeps
Applications / Access / Requests / My Applications stable for global app admins;
Requests stays active across the round trip and refresh. Ordinary members retain
My access / Company apps / My requests; assigned App admins retain scoped Manage access.
No authorization or catalog visibility changes were made.

Web-only deployment: `catalog-navshell177-7c31e99eaaa1903c`.
API/operator remain `catalog-access177-04eff2abd6437a0a`; API container/binaries,
schema177, all20 durable projections and the six non-web services were preserved.
Typecheck, eight affected suites (209 passed, two existing expected failures) and
production build passed. Actual administrator four-route/refresh and member
three-route browser checks passed; assigned-role coverage is regression-test based.
Owned browser sessions were logged out and viewport override reset.

Evidence: `/home/ubuntu/app-access-staging/company-apps-stable-nav-20261004/acceptance.json`, SHA256 `863e32912cf10e0fc1b5c40805bad721139babaf589e533a529dc06a5fc3b7fb`.
This documentation follow-up is outside the frozen runtime artifact.

## AA-10 grant views, retention and hostname reuse — 2026-10-04

Accepted on the same isolated test CP, now clean schema179. Current grants default
to active/disabled; scheduled and unavailable subjects remain explicit Current
filters, while revoked/expired grants are under History. Global and assigned-App-admin
views retain server-side filtering, pagination and their existing authority.

Schema178 retains revoked grant rows for 90 days from revocation and grant-change
audit records for 365 days; expired-only grants are not purged by this policy.
Approval history retains the original grant identity after row removal. Schema179
allows a new app UUID to reserve a hostname only after confirmed withdrawal and
archival of its prior owner, preserving historical revisions and authority.

See [the acceptance record](AA-10-followups179-acceptance.md) for exact source/build
hashes, isolated tests, live checks, the preserved failed comparator and its
independent audit-append proof, cleanup, and qualification limits. These are
follow-ups to Story 11, not new story numbers; prior schema176/177 acceptance
records above remain unchanged.
