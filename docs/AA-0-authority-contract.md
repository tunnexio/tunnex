# AA-0a App Access authority contract

Status: local implementation contract for review; no shipping capability is implied.
Prepared 2026-10-03 against feature/app-access `5c1093e87db358cab06080cc272321a2e074802f`.
Companion: [epic](EPIC-app-access.md); transport qualification belongs to AA-0b.

## Authority and entitlement decisions

The control plane is the only authority for organization membership, application
intent, grants, login and app sessions. Proxy and connector status are observations,
not permission grants. VPN enforcement mode never bypasses App Access decisions.

The epic's enterprise/group assumption is stale against this baseline. This is one
binary with runtime named feature entitlements, not two build-tag editions.
Groups and the ordinary Zero Trust engine are available in Community; existing
group endpoints have permission/service gates rather than a paid-group gate.
Do not alter their availability for this epic.

Implementation choice: add a distinct `licence.FeatAppAccess = "app_access"` to
the central feature map, included in Trial, Starter, Growth and Scale, absent in
Community and unknown tiers. This carries the epic's proposed paid gate using
the actual licensing seam; it makes no new SKU or pricing promise. Add a separate
organization opt-in, default false. Entitlement alone neither enables an org nor
publishes an app. AA-1 must test the feature census and expiry behavior. Commercial
release positioning remains a release decision, not a reason to invent an edition.

After entitlement loss, deny new app-content requests and expire stream leases;
keep console authentication, read-only configuration inspection, disable/revoke
and own-session sign-out available. Licensing must never prevent removal of access
or prevent console access needed to renew a license. Configured SSO login keeps
its existing independent behavior.

| New permission | Owner/admin | Member | AI-only and machine roles |
| --- | --- | --- | --- |
| `app_access:view` | Configuration, checks, inventory | No | No |
| `app_access:manage` | Opt-in, drafts, check, publish, disable, rollback, delete | No | No |
| `app_access:grant` | Grant inventory, edit, preview, revoke | No | No |
| `app_access:use` | Own catalog/launch; explicit grant required | Own catalog/launch; explicit grant required | No |
| `app_access:session_manage` | Organization session metadata/revoke | No | No |
| `app_access:event_view` | App decision metadata in existing event view | No | No |

Evaluate membership role sets through `rbac.CanAny`, never a role string check.
Multi-role users receive the union of named capabilities. CP administrator status
alone does not confer tenant app-content access. Register view/use/event-view as
non-mutating in `IsMutating`; additionally require a verified human session for
launch/content. Mutating admin permissions preserve the existing verified-email
gate. Own-session revoke requires a verified human session, independent of admin
session management and entitlement. API tokens, machine credentials and agent
principals cannot launch or consume browser apps in v1. Generate the web RBAC
mirror; hidden controls are only UX.

An allow decision requires all of: entitled and opted-in org; exact active host;
published active revision and matching assigned live connector; current active
user and org membership with use permission; verified email; no required password
change or existing local-login MFA gate; live parent login and app session; and at
least one enabled same-org explicit user/group grant valid at decision time.
Grant intervals are `[starts_at, expires_at)`; absent bounds are unbounded. Group
membership is current, not snapshotted at launch. Overlapping allows form a union;
revoking one does not deny a surviving valid allow. No Everyone, implicit admin
grant, VPN-IP expansion or origin-role claim. A grant controls entry, not the app's
own read/write roles. The app's login remains unless separately integrated.

## Session and browser boundary

Local password and configured SSO converge after existing login gates. Preserve
mint-time AuthMethod: current org MFA enforcement applies to local-password login,
and SSO is exempt under existing behavior. Do not infer verified MFA from SSO,
enroll per-app factors, or add per-app step-up; those are AA-9.

The qualified domain-settings extension permits a controlled app base domain on
an independent registrable site, or exactly the portal hostname (portal
`internal.tunnex.app`, app `demo.internal.tunnex.app`). Other same-site topologies
remain refused. Exact normalized ASCII hostnames are installation-wide unique,
without wildcard registrations or path-prefix multi-app hosting. Reject console
host aliases, IP literals, ambiguous Host/authority values and unknown hosts before
lookup. Edge certificates cover approved hosts only, supplied by the operator or
a separately qualified certificate lifecycle. Unrestricted on-demand issuance is
not accepted. The portal-parent topology requires host-bound HTTPS console cookies,
exact browser-origin checks for mutations including login, portal frame denial,
origin-keyed documents, and removal of private-app `Clear-Site-Data` responses.
Ordinary application cookies on a shared site are not a guarantee of isolation
between mutually hostile app operators. Local fixture domains prove only their
own test behavior.

Only a CP administrator with a verified human browser session may change the
deployment-wide domain settings. The database version prevents stale saves;
changes apply to new app addresses and subsequent canonical login links. Existing
published hostnames and grants remain unchanged. Customer-managed DNS, certificates
and IdP callback registrations must cover the selected addresses. IP access may
serve the console; apps never share its browser origin through IP/path routing.

Use host-only `__Host-tunnex_app_session` and browser nonce cookies with Secure,
Path=/, HttpOnly and SameSite=Lax; never set Domain. Reject duplicate reserved
cookies and origin attempts to set the reserved names. Strip app session/nonce
cookies, console credential cookie names and internal service headers before
forwarding; preserve other app cookies within the qualified exact-origin rewrite
contract. App content never runs on the console origin. Do not trust inbound
user/forwarded identity headers or inject authenticated-user headers in v1.

Direct GET/HEAD and catalog launch use a registered app identifier plus normalized
relative path (no scheme, authority, backslash, control character or `//` target).
Validate decoded path representation and preserve an allowed query for navigation
without logging it. A proxy-set nonce is bound to a pending server-side launch
transaction. Console authentication returns through that transaction to the exact
registered host. Issue a 32-byte random code with a 60-second TTL; store its hash,
nonce hash, app/host/org/user/parent session and relative target. Redeem atomically
once using proxy service identity and matching browser nonce, consume the callback
before upstream traffic, then redirect to a clean URL with no-store and no-referrer.
Failed code/nonce redemption creates no cookie. Never replay POSTs after login;
show a sign-in-required page and ask the user to resubmit deliberately.

App sessions use independently random opaque tokens stored by hash and indexed by
org/app/user/parent login. Default absolute maximum is 8 hours; idle is 30 minutes.
App settings permit absolute 5 minutes–8 hours, idle 1–30 minutes, idle <= absolute;
operators may lower ceilings. App absolute expiry is the earlier of app lifetime
and parent ExpiresAt. Grants are reevaluated rather than baked into session TTL.
Both parent and app idle expiry matter: add a non-touching authoritative parent
validation operation; do not call the existing sliding `session.Store.Get` on
every app request/lease renewal, which would keep console login alive accidentally.
Only accepted foreground browser requests refresh app idle; automated lease renewals
and passive SSE/WebSocket keepalive do not. Reconnect after idle expiry requires a
fresh authorized handoff. Existing Redis keys/store behavior stay compatible.

Unsafe app methods require same-origin Origin or same-origin Referer fallback;
missing/bad/cross-app evidence is denied. WebSocket upgrade requires matching
Origin. Do not require `X-Tunnex-CSRF` on arbitrary origin app forms: that header
belongs to console APIs. Preserve upstream CSRF protection and deny arbitrary
credentialed cross-origin CORS. Lax cookies alone are insufficient because app
hosts may be same-site. External OAuth callback and cross-site POST flows require
specific qualification; do not silently add exceptions.

## Lifecycle and API sketches

These are AA-1 OpenAPI inputs, not hand-maintained clients. Prefix organization
routes with `/api/v1/organizations/{orgId}/app-access`. Tenant lookup precedes identifier
projection; foreign/unknown identifiers return a generic 404. Member projections
never disclose origin addresses, gateway metadata, grants or other users' sessions.

| Method and suffix | Contract |
| --- | --- |
| GET/PATCH `/settings` | Read availability/opt-in; change opt-in with expected version and manage permission |
| GET/POST `/applications` | Paginated privileged inventory/create draft; server-issued ID/version |
| GET/PATCH `/applications/{id}` | Detail/edit draft only using expected version; immutable active revision remains |
| GET `/applications/{id}/revisions/{revision}` | Configuration digest, immutable reviewed fields, status timestamps |
| POST `/applications/{id}/checks` | Bounded check operation for exact draft digest; no origin redirects |
| POST `/applications/{id}/publish` | Expected version, reviewed digest and fresh check IDs; idempotency key |
| POST `/applications/{id}/disable` | Durable immediate authority withdrawal, independent of origin health |
| POST `/applications/{id}/rollback` | Stage a previously validated revision; recheck current prerequisites |
| DELETE `/applications/{id}` | Only disabled and confirmed withdrawn; retain audit/tombstone host ownership |
| GET `/operations/{id}` | Desired/applied revision, individual readiness, pending/confirmed/failed and safe errors |
| GET/POST/PATCH `/grants[/{id}]` | Same-org app and current user/group subject; validity and optimistic version |
| POST `/grants/{id}/revoke` | Idempotent removal of this allow; report union-aware affected sessions |
| POST `/applications/{id}/effective-access` | Grant permission; preview current decision, never bypass it |
| GET `/my-applications` | Own authorized cards only, no caller-supplied user identity |
| POST `/applications/{id}/launch` | Verified cookie user, current grant, safe relative return and pending nonce binding |
| GET/DELETE `/my-sessions[/{id}]` | Own redacted app session metadata/scoped revoke; current session label |
| GET/POST `/applications/{id}/sessions[/revoke]` | Session-manage permission; exact selected/all-app scope and operation status |

Separate internal machine-only endpoints perform proxy route lookup, code redemption,
new-request authorize and stream-lease renewal. Dedicated proxy service credentials
have only those verbs; enrolled gateway certificates have only assigned connector
configuration/status/data verbs. Neither identity can create grants or invoke human
management APIs. Bind decisions to org/app/host/user/app session/parent session/
assigned gateway/revision and a server-issued stream identifier. AA-0b chooses
transport authentication implementation; TLS and explicit purpose separation are
required regardless of library. Browser-supplied dial targets are never accepted.
Gateway identity follows the existing authenticated leaf-certificate serial lookup
through `AuthenticateCert`: resolve the current active node and its organization,
then verify current app assignment and revision. Certificate CN is a node name,
not trusted organization authority; do not require or trust a fabricated org OU.
Renewals must recheck current serial/node state so rotation/revocation is effective.

Publication changes desired revision first; status is pending until the exact
digest is acknowledged by connector and proxy and all fresh checks are satisfied.
Switch active authority atomically, drain old-revision streams within the lease
bound, and refuse mismatched revision traffic. Failed staged edits leave prior
active revision serving; disable immediately denies authority even during an edit.
Sensitive origin/connector/domain/TLS/session-policy edits invalidate check evidence.
Hostname edits create a draft registration for the new exact hostname; the old
exact hostname remains active until the atomic revision swap, then is tombstoned
until confirmed routing/session withdrawal. Never mutate the serving host in place.
Timeouts return an operation ID for readback, not an invitation to repeat a mutation.
Delete retains the hostname tombstone until old routing/session/connector state is
confirmed withdrawn; do not reuse a host merely because the app row disappeared.

## Withdrawal, outages and resource acceptance

Every new browser request and protocol upgrade obtains a current CP decision; no
positive authorization cache. The request's long-running body/response and every
SSE/WebSocket stream need an authority lease. Maximum stale authority target is
5 seconds from committed authority change or loss of authoritative service.
Renew every 2 seconds with a maximum 4-second lease measured from decision start
at the proxy (response latency consumes validity), leaving 1 second for close and
scheduling margin. Reject late renewals. Bind lease lifetime to earlier login,
app idle/absolute and current matching-grant expiry. Use monotonic timers; do not
depend on synchronized wall clocks or push notifications for the bound.

Acceptance measures fresh-request denial and last forwarded stream byte after
each committed grant/user/group/membership/app/gateway/session/opt-in/license
withdrawal, parent logout/password reset and grant expiry. Exercise lost push,
proxy/connector restart, CP failure and Redis failure with SSE, WebSocket, upload
and long download. New requests fail closed on missing CP/Redis/DB authority;
streams close when their existing lease ends. An admin response says withdrawal
requested until operation readback confirms bounded termination. Already delivered
content cannot be recalled and an origin-accepted mutation cannot be undone.

Initial finite limits for AA-0b measurement and later configurable implementation:

| Resource | Default / rule |
| --- | --- |
| Request headers | 32 KiB total; 100 fields; 8 KiB request target; refuse ambiguity/smuggling |
| Upload body | 64 MiB streamed cap; reject known oversized length before forwarding; chunked overflow closes, no retry |
| Downloads / streams | Stream without whole-body buffering; absolute app lifetime and lease bound apply |
| Queued bytes | 256 KiB per stream per direction; 32 MiB per channel; backpressure rather than growth |
| Concurrency | 32 streams/app, 128/connector, 256/proxy, 16/session; refuse excess with safe 429/503 |
| Timing | Headers 10s, origin connect/TLS 5s each, response headers 30s, blocked write 15s; SSE/WS exempt only from ordinary body idle timeout |
| Connectivity probe | 10s overall, one exact origin, no redirects, bounded output and rate limit 6/min/app |

These are proposed enforceable ceilings, not measured capacity claims. AA-0b must
record supported slow-reader/cancellation behavior and revise limits if the selected
transport cannot enforce them. One public proxy and one selected enrolled gateway
per app are the supported initial topology; no failover or HA claim. Origins must
support the published external URL. Exact scheme/host/port and TLS server name
are registered; dial-time DNS validates every candidate address against explicit
destination constraints. Private ranges can be allowed; loopback, link-local,
metadata, control-plane endpoints and reserved targets are denied by default.
No global TLS skip-verify. Origin firewalling must prevent browser/public bypass.

## Textual wireframes and wording

Standalone sidebar: **App Access — Open private web apps in your browser**.
Root selects the authorized landing; admin content access still requires a grant.

```text
Applications                         [My Applications] [Add application]
[Search] [Publication filter]
Name | Browser URL | Publication | Connector health | Last observation
Draft / Pending / Published / Disabled are distinct from Healthy / Unavailable.

Add application: Application -> Connection -> Access -> Review & publish
Application: name, description, bundled icon, exact origin, connector, hostname,
             absolute/idle limits. [Save draft] preserves inputs.
Connection: eligibility / origin DNS / connect / TLS / public DNS / certificate;
            each check shows its time, digest and blocker. [Check again]
Access: explicit users/groups, enabled state and validity. No Everyone or MFA toggle.
Review: exact revision, audience, browser URL and limits. [Publish reviewed revision]
Pending: Configuration saved; waiting for connector and proxy confirmation.

Access                               [Application filter] [Add grant]
Application | User/group | Valid from/until | Enabled | [Edit] [Revoke]
Application detail uses the same records; preview states overlapping grants survive.
Disable: New access will stop; active connections end within the qualified bound.
        [Disable] -> Withdrawal requested -> Withdrawal confirmed.

My Applications                      [Search] [My sessions]
[Name / description / Open] ...
No applications assigned: Ask your administrator to assign an application.
My sessions: Application | Started | Last foreground use | Expires | Current | [End]
Ending this app session does not sign you out of Tunnex.
Signing out of Tunnex ends app sessions bound to that login.
```

Show loading, load failure/retry, feature unavailable, no assigned apps, session
expired and access denied separately. Unauthorized direct URLs disclose no private
topology or tenant/application existence. Connector interruption says connection
interrupted; do not promise a mutation was retried. Explain: **The application may
ask you to sign in again. Tunnex controls access to the application, not its own
account permissions.** Narrow-width, keyboard and focus-restoration behavior follow
the epic's screen-census/responsive acceptance.

## AA-1 integration inputs and review risks

AA-1 owns OpenAPI and generated clients, runtime feature census, org opt-in,
named RBAC mirror, tenant-safe registry/revisions and audited optimistic mutations.
Use composite org-scoped relationships for app/gateway/subject references. Allocate
migrations from live main at implementation time. Disable/revoke must stay possible
after feature loss. AA-2 owns the current-grant evaluator; AA-3 owns capability and
desired/applied revision facts. No AA-1 endpoint may advertise live traffic until
AA-3–6 satisfy publication. Tests must include multi-role membership and machine
refusal rather than only owner/admin string cases.

Unresolved release qualifications: transport/library and license fit; measured
resource limits and 5-second closure under failure/load; external OAuth/cookie
compatibility matrix; actual approved certificate lifecycle; installer domain
validation and public edge deployment path. These are qualification work, not
permission to publish unsupported behavior. The named tier mapping above is the
local implementation proposal; commercial release changes must use the central
feature map without changing unrelated capabilities.

## Inspected source seams

- [RBAC](../apps/api/internal/rbac/rbac.go): named capabilities, role policy, generated mirror and IsMutating fail-closed read allowlist.
- [Authorization](../apps/api/internal/http/handlers.go): authorize at lines 73–110, role-set permission checks, password wall and verified mutation gate.
- [Runtime entitlements](../apps/api/internal/licence/entitlements.go): distinct features and tierFeatures; unknown tiers deny named features.
- [Edition shim](../apps/api/internal/enterprise/edition.go): compatibility only; explicitly not the entitlement source.
- [Groups](../apps/api/internal/http/policy_handlers.go): ListGroups at lines 70–100, permission and service availability checks.
- [Session auth](../apps/api/internal/http/session.go): current active-user/membership lookup and console CSRF guard.
- [Redis sessions](../apps/api/internal/session/session.go): Get at lines 106–130 touches idle TTL; parent non-touching validation is new work.
- [Session defaults](../apps/api/internal/config/config.go): lines 213–214, parent idle 24h and absolute 720h; app 30m/8h is deliberately separate.
- [SSO](../apps/api/internal/http/sso_handlers.go): lines 45–72 distinguish paid configuration from surviving configured login.
- [MFA gate](../apps/api/internal/http/mfa_enforce_handlers.go): lines 116–143, immutable local-password method gating and SSO exemption.
- [Gateway identity](../apps/api/internal/http/agentchannel.go): authenticateAgent at lines 446–481 resolves leaf serial to current node/org; [CA](../apps/api/internal/agentca/ca.go) SignCSR stores commonName, not org authority.

This document records decisions and acceptance targets. It is not evidence of
implemented APIs, session withdrawal, rendered UI or qualified transport.
