# Tunnex Beam authority and transport contract

Status: **BM-0 feasibility locally accepted. Actual authenticated desktop-to-browser serving, native TCP 443 transport and package contents are qualified; later platform/deployment acceptance remains open. This document does not assert production readiness.**
Prepared: 2026-10-06. Stories: BM-0a and BM-0b.
Core worktree: `/private/tmp/tunnex-beam-plan`, `extra-feature`, baseline `7ed12a91`.
Client worktree: `/private/tmp/tunnex-client-beam`, `extra-feature`, latest pulled main `9b71d19`.

## Customer journey and ownership

An operator configures the Beam domain and TLS, then an organization administrator enables publishing for an explicit audience. A permitted developer uses desktop Beam to select one local app, grant permitted reviewers and set expiry. Reviewers use existing Tunnex browser login and optional MFA. Sharing is self-service inside policy; an organization administrator does not approve every normal share.

Beam remains a separate developer feature because the publisher needs the desktop runtime. Reviewers need only a browser. The existing VPN connection and privileged helper do not authorize or carry Beam traffic.

| Actor | Allowed action | Required authority |
| --- | --- | --- |
| Installation operator | Configure serving domain and TLS; drain/disable a serving installation | Existing installation ownership plus explicit operator permission |
| Organization administrator | Enable Beam; set allowed publishers/reviewers, TTL, limits and MFA | Current membership and Beam policy-management permission in that organization |
| Publisher | Create, inspect and manage own shares and their audience | Live human desktop account authority, current organization membership, publishing permission and delegated audience policy |
| Reviewer | Open a particular share | Live human browser parent login, current membership, explicit matching share grant, optional fresh verified MFA and serving authority |
| Administrator viewing content | Open a particular share | The same explicit content grant and browser rules as any reviewer |

Users/groups remain existing organization identities. No anonymous links, external invitation flow, workload/agent publishing or implicit Everyone grant enters the first release.

## Immutable binding and authority checks

| Binding field | Meaning and enforcement |
| --- | --- |
| Installation/server | Publishing credential is pinned to the control plane that issued it; account/server switching retires pending operations and serving |
| Organization | Every resource, audience and credential lookup is scoped to the current organization |
| Publisher | A human actor whose current source authentication family and membership remain valid |
| Connector | One proof-of-possession identity scoped to the share; certificate/key material never enters the renderer |
| Share | One server-owned resource with a randomly allocated hostname |
| Target revision and digest | One fixed local protocol/address/port/trust configuration captured in main; no request can choose a destination |
| Serving generation | Exclusive current connector generation; replaced generations cannot serve or renew |
| Authority version | Incremented on material policy, grant and lifecycle changes |
| Purpose | `beam_proxy`; never `browser_proxy` or `origin_check` |
| Expiry | Absolute server time, also capping credential, browser-session and active-stream authority |

The reusable `apptransport.Binding` carries share ID in its `AppID` slot and connector ID in `GatewayID`. This is an internal wire adapter; Beam uses a separate broker, `/beam/channel` route and authority callback. It does not enroll a laptop as an App Access gateway or treat app grants as Beam grants.

Each admission and renewal validates the current committed authority. Certificate validation identifies a credential, not a content grant. Headers confirm a server-owned binding and cannot choose another actor, target, share or audience. Persistent Beam APIs now issue proof-of-possession connector certificates and retain the source human CLI credential or browser session relationship. SQL and real proxy/native integration tests exercise those checks.

## Transport decision and local implementation

**Use an unprivileged native Node connector under Electron main**, based on standard-library TLS and HTTP. The native connector consumes the Go outbound CONNECT transport without another binary, separate installation or privileged helper. Actual Electron main/preload/renderer wiring and encrypted production PKCE credentials are implemented and locally exercised. macOS ARM64 and Windows x64 directory packages include the final main/renderer modules; Windows runtime execution remains BM-10 qualification.

| Area | Contract |
| --- | --- |
| Connector transport | TLS 1.3, trusted server chain and mTLS identity, HTTP/1 CONNECT to `/beam/channel`; production endpoint defaults to 443 |
| Local target | Exact `127.0.0.1` or `::1`, validated integer port 1–65535. HTTP and HTTPS with verified local certificate identity or a fixed trust anchor are implemented. No global insecure TLS switch. |
| Inbound networking | The connector feeds the accepted outbound TLS socket into an unbound HTTP server. It calls no `server.listen()` and no VPN helper. |
| Browser traffic | Proxy reuses an admitted channel to request the fixed local app. The publisher does not receive the user's Tunnex credential. |
| Existing restrictions | Keep App Access loopback refusal intact. Beam is a distinct audience and loopback-only runtime. |
| Header boundary | Exact binding headers and stream ID required; credential/identity/forwarding headers stripped before origin requests; forwarding host/protocol constructed by the connector |
| Target boundary | Reject absolute request targets, CONNECT, TRACE, alternate targets, invalid ports, non-loopback addresses and header injection; redirects never become a server-side dial to another destination |
| Cookies and redirects | Tunnex and Beam cookies stay out of the app. Supported app cookies become host-only/Secure. Broader cookie domains and external redirect destinations are refused in the spike. |
| HTTP compatibility | Native proof covers HTML, application cookies, form bodies, safe relative redirects and concurrent assets/SSE/WebSocket. Genuine Vite module edits produce HMR and updated proxied module bytes. No body rewriting. Full browser/application matrix remains BM-5/BM-10. |
| Long traffic | SSE and WebSocket use the same authenticated socket and authority lease. Closing it tears down associated origin requests/sockets. |
| Lease | Four-second maximum channel lease, renewal every two seconds, independent expiry watchdog. Five-second maximum stale-authority is the customer acceptance ceiling. |
| Capacity | 128 total broker reservations; Beam limits 64 per organization and 34 per share across active and pending admissions. Desktop keeps two idle channels and at most 32 active channels. Proxy request limits are 256 global, 64 per organization, 32 per share and 16 per browser session. App Access limits remain unchanged. |
| Limits in current native seam | 32 KiB headers, 16 MiB request/response body streams and five-second CONNECT handshake deadline. WebSocket streams validate masking, opcodes, fragmentation and canonical lengths with a 1 MiB frame and 16 MiB fragmented-message cap; v1 does not negotiate compression. Real slow-reader buffer plateau, concurrent serving and bounded withdrawal passed locally. |

## Lifecycle and UI contract

| State or trigger | Publisher UI | Reviewer UI and serving effect |
| --- | --- | --- |
| Not enabled or setup incomplete | Specific policy/setup reason; no Create action | Feature unavailable without exposing installation secrets |
| Starting | Creating/connecting; no Ready inferred from an open local port | No content admission before authority and transport readiness |
| Active and ready | Live, canonical URL, current expiry and audience | Open after login/grant/MFA checks |
| Local app unavailable | Check app/retry; retain URL and expiry | Origin unavailable; no redirect to another target |
| Connector disconnected | Reconnecting/offline; retain original expiry | Existing streams close; new requests unavailable |
| Paused | Resume only under current authority/readiness | Deny new access and close open traffic |
| Stopped/expired/revoked | Terminal; offer a new share instead of resurrection | Deny new access and close open traffic by lease deadline |
| Grant removal | Show remaining effective audience | Only users lacking any remaining valid grant lose access |
| Publisher logout/expiry/role/member loss | Retire serving and in-flight operations | Revoke that publisher's shares and streams |
| Window close/full quit | Qualified tray behavior versus explicit exit; truthful status | Window close may keep a running app; full exit cannot retain a serving orphan |

Lifecycle, connectivity and authority are separate facts. A redacted UI projection may never make a stale or terminal share Live. Pause/resume preserves the hostname and original expiry; extension is explicit and policy bounded. Changing a local target requires a new share in v1.

The original spike dashboard and synthetic sign-in still prove only injected transport authority. The separate implemented product now has Beam navigation, persistent policy/grants/lifecycle, real local and SSO parent-session checks, MFA authority and publisher source-credential checks. These are qualified separately through the actual CP/proxy/native path; fixture-only success is not a customer walkthrough.

## Domains and production admission boundaries

Allocate at least 128 random bits per hostname under an installation-approved Beam base domain, unique across tenants. Prefer a separate registrable domain from CP and preserve qualified `appdomains` cookie/CSRF boundaries. Wildcard DNS/TLS setup is operator work once; developers do not create individual DNS records. Arbitrary CP sibling domains are not assumed safe.

Production reviewers require a host-only secure Beam browser session created through a one-use parent-bound launch exchange. The local spike uses HTTP on loopback and explicitly synthetic fixture reviewer authority, while the connector link itself uses verified TLS 1.3 and mTLS. The synthetic sign-in route and fixed metadata must never be wired into production API/proxy handlers or desktop startup.

The Go fixture exists under a development command and is not in deployment images. Client fixture programs live outside `src` and are excluded from desktop packages. The production Beam runtime activates only through current account, installation and organization authority.

## Completion boundary

The approved local operator/publisher configuration and actual desktop created
a persistent admin-only share. Following normal HTTPS console sign-in, fresh
nonce handoff and Continue, Chrome rendered the task-owned local app through
the running desktop connector with VPN disconnected and no helper socket.
Approved Pause/reload/explicit Resume preserved the original encrypted source
credential, share ID, canonical URL and expiry. The recorded browser screenshot
is in [current qualification](BEAM-local-qualification.md). BM-0 is now locally
accepted; it does not close later stories' independent release acceptance.

BM-0 transport, actual Electron wiring, real PKCE login, genuine Vite HMR and macOS/Windows package contents are locally exercised. The persistent native authority matrix passes. macOS refused an unprivileged host port-443 bind, so a separate nonroot Linux Docker fixture ran the real persistent-authority test with the native Node 24.21 connector on exact TCP 443. HTTP, SSE and WebSocket serving and stop/pause withdrawal passed, with all three streams closing in 1.825 seconds. The local Docker browser endpoint separately verifies wildcard TLS on published TCP 443. These are local transport qualification results; they do not imply Windows execution or production public-certificate qualification. Persistent product implementation and its tests do not close later stories until their UI, failure, topology and delivery acceptance is recorded.
