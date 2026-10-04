# App Access browser proxy (AA4 / AA5)

This separately built service serves a root application through an outbound
TLS 1.3, mutual-TLS HTTP/1 CONNECT stream initiated by its enrolled gateway.
The public proxy never dials a gateway listener. Browser traffic has purpose
`browser_proxy`, an immutable published serving generation/revision/digest,
exact organization/gateway/application/hostname and authority version. It
cannot reuse a draft `origin_check` channel.

**Production serving remains withdrawn until AA6 publication.** AA5 adds the
proxy launch/redemption consumer, while the control plane has no published routes. The node's optional browser observer accepts only authenticated
withdrawal and an empty assignment array; positive assignment decoding belongs
to AA6. Positive test fixtures inject explicit test-only serving/session
authority and do not demonstrate a published application in the live product.

## Build and configure

`go test -race ./...` and `go build ./cmd/app-proxy` use pinned Go 1.26.8.
Dependencies are the local stdlib-only `packages/apptransport` and the
repository-pinned `golang.org/x/net v0.57.0` public-suffix data/helper.
Private authority wire models are generated from the central OpenAPI schema;
run the root `make generate-app-proxy` / contract check target after changes.

Both listener addresses default empty; an unconfigured process exits disabled.
Enabling requires all of:

- `TUNNEX_APP_PROXY_PUBLIC_ADDR`, `TUNNEX_APP_PROXY_GATEWAY_ADDR`,
  `TUNNEX_APP_PROXY_BASE_DOMAIN` (exact application host suffix).
- `TUNNEX_APP_PROXY_CONSOLE_BASE_URL`: one HTTPS console root on a different
  ICANN registrable domain. Credentials, arbitrary paths/query/fragments, IPs,
  localhost, unknown suffixes and private PSL hosting domains are unsupported.
  Explicit valid console ports are allowed; public app Hosts remain portless.
- `TUNNEX_APP_PROXY_TLS_CERT_FILE`, `TUNNEX_APP_PROXY_TLS_KEY_FILE`: operator
  browser-trusted public application certificate.
- `TUNNEX_APP_PROXY_GATEWAY_TLS_CERT_FILE`,
  `TUNNEX_APP_PROXY_GATEWAY_TLS_KEY_FILE`: separate enrollment-CA signed leaf
  with SAN `tunnex-app-proxy`; `TUNNEX_APP_PROXY_AGENT_CA_FILE` verifies enrolled
  gateway client certificates.
- `TUNNEX_APP_PROXY_AUTHORITY_URL`, `TUNNEX_APP_PROXY_AUTHORITY_CA_FILE`,
  `TUNNEX_APP_PROXY_AUTHORITY_SERVER_NAME` (default `tunnex-app-authority`):
  direct private HTTPS authority port. TLS 1.3, explicit trusted roots, hostname
  verification, no environment proxy or redirects.
- `TUNNEX_APP_PROXY_CREDENTIAL_FILE`: private mode 0600/0400 file with a
  dedicated `tnxap_` credential. It is sent as `AppProxy`, never as a human
  Bearer token, cookie, browser identity header or gateway certificate.

The node opt-in `TUNNEX_APP_PROXY_URL` uses the existing rotating
`GetClientCertificate` callback and enrollment CA with server name
`tunnex-app-proxy`. Ordinary WireGuard control keeps its existing TLS behavior.
There is no default Compose service or public deployment in this slice.

## Authority, HTTP behavior and limits

Every public request performs route lookup and authorization. There is no
positive route/session cache. Gateway acceptance verifies the actual mTLS leaf
serial against the dedicated authority and compares all tuple headers with
the server-owned route. Headers do not establish tenant identity. Session and
channel leases last at most four seconds, renew every two seconds, and have
independent expiry timers. A stalled authority callback cannot extend a socket
lease; callback slots stay occupied until the callback actually returns.

Public Hosts are strict ASCII DNS names without a port/trailing dot/IP;
duplicate Host is rejected by the HTTP parser and direct handler guard.
Targets are relative and at most 8192 bytes. CONNECT, TRACE, malformed methods,
unsupported Upgrade, cross-origin unsafe methods and WebSockets without an
exact HTTPS Origin are refused. Known control/session cookies, channel/service
headers and forwarded identities are removed; ordinary application
Authorization, X-Auth-Token, X-App-CSRF and cookies are retained. Forwarding
metadata is constructed from the direct TLS request. Origin Set-Cookie cannot
set reserved cookies or another domain; accepted cookies become Secure and
host-only. Same-origin redirects map to the public HTTPS hostname. Bodies are
never rewritten; external redirects/OAuth and cross-site POST compatibility
remain unsupported and need later qualification.

Origin transport re-resolves every request, validates **all** DNS answers,
refreshes all control-host aliases and fails closed if their DNS is unavailable.
It dials literal validated addresses with the registered Host/TLS SNI, system
roots plus reviewed CA, no redirects or environment proxy. Private targets
need explicit private-contained CIDRs. Reserved/metadata/loopback/control
addresses remain forbidden regardless of CIDR. Policies use the shared
canonical 32-CIDR / 32-KiB / eight-CA validation and digest.

Public sockets are bounded to 256, gateway sockets to 128 including TLS
handshake, with public 10-second and gateway five-second header/handshake
limits. Logical channels/admission/retired authority callbacks are independently
bounded by the broker. Public request counts are 256 globally, 128 per gateway,
32 per app and 16 per opaque app-session cookie hash. Request headers are
32 KiB / 100 fields, known-length upload bodies 64 MiB streamed, response headers 32 KiB. Chunked
request uploads are currently refused, including TE+CL ambiguous requests (the
Go parser otherwise removes CL before the handler). Full chunked ingress awaits
qualification; no custom HTTP framing parser is introduced.
Origin connect/TLS is five seconds; response headers 30 seconds. Writes have a
15-second blocked-reader deadline, overridden immediately at lease expiry;
upload reads and hijacked WebSockets are also interrupted at expiry. Declared
  unauthenticated bodies have a ten-second drain bound; authorized body reads
  require progress within fifteen seconds. EOF/close resets never clear an
  expired or finished response deadline. GET/SSE background reads are unaffected. SSE and
WebSocket bodies keep flowing while current leases renew.

Node browser runners are bounded to 128 globally / 32 per assignment, prewarm
one idle channel per assignment (broker maximum two), and replenish when a
stream starts. There is no guaranteed fair allocation under global saturation;
requests fail boundedly when capacity is unavailable. At most 64 assignments
are accepted. This is a count-bound proof with streamed copies, **not** a
measured hard RSS/256-KiB-per-direction memory guarantee or capacity benchmark.
Slow readers, long-running streams, operational shutdown and deployed load
still need AA7 rollout qualification.

## Evidence

Proxy tests exercise real browser TLS requests through a real outbound mTLS
broker and shared exact-origin forwarding: forms, assets, redirect/cookie
rewrites, SSE cancellation, a valid RFC6455 handshake with masked client frames
and multiple echoed frames, WebSocket cancellation, ordinary application
credentials and refusal after test authority withdrawal. Lease tests cover
blocked ordinary uploads/downloads, expiry before hijack, ignored-context late
renewal, concurrency/callback bounds and raw parser duplicate Host/length
refusals. Node tests run its actual production BrowserPool against a local mTLS
broker, including two SSE streams plus a third form/asset request and withdrawal.
Shared tests cover streaming private-CA/SNI verification, unknown CA/wrong name,
per-request DNS changes/mixed forbidden answers/control aliases and no proxy.

These fixtures inject loopback physical dial mappings only after validating
logical test destinations. They never disable TLS verification and do not
borrow a running gateway identity or manufacture a production publication.

## Browser launch (AA5 in progress)

The reserved `/__tunnex_app/start` and `/__tunnex_app/redeem` paths never reach
an origin. Start accepts a safe relative navigation target, looks up the current
server-owned published route, generates a random 32-byte nonce and registers
its hash/route/target as a pending server transaction over private TLS. Only a
successful bounded registration can set `__Host-tunnex_app_nonce` and redirect
to the fixed trusted console `/app-access/launch` path. The console sees the
SHA-256 of the exact 43-character base64url nonce string, server-owned org/app
IDs and relative navigation; it never sees the nonce, app cookie or parent token.
The pending transaction/nonce lasts at most ten minutes for login/MFA; the
subsequently issued hashed, single-use launch code lasts sixty seconds.

Redemption accepts one exact code plus the app-host nonce cookie. The dedicated
proxy credential calls the generated private redemption endpoint; successful
server consumption returns the opaque app-session token and bound relative
navigation. The proxy sets a Secure/HttpOnly/Lax/Path=/ host-only app cookie,
clears the pending nonce and redirects with HTTP 303 to a clean relative URL.
All handoff responses use no-store/no-referrer. Invalid, duplicate, expired,
cross-host, mismatched and replayed handoffs issue no cookie and preserve any
newer pending nonce. Reopen a fresh My Applications link after pending expiry.
Concurrent pending starts rotate this single cookie, so only the latest matching
flow succeeds; already logged-in app tabs share the normal host-only app session.

Only GET/HEAD with no app session, or an exact authenticated authority response
`app_session_invalid`, may restart login. Grant/parent/feature/publication denial
and service-credential failure remain unavailable. POSTs and WebSockets never
replay after login. Actual single-valued Sec-Fetch mode/destination/user evidence
is forwarded as optional generated metadata; it is not proof of a human action.
Passive assets/heartbeats/stream renewal must not refresh app idle authority.
Private JSON disables HTML escaping and is bounded to 64 KiB to preserve full
8192-byte target/referrer limits; public framing bounds remain unchanged.

HTTPS cookie-jar fixtures qualify nonce/session audience and code cleanup; typed
private-client fixtures qualify generated payloads and selective session errors.
Publication/session authority in proxy positive fixtures is explicitly injected;
actual SQL/Redis launch and durable parent revocation require the API integration
and central browser acceptance gates. Native unpublished apps remain unavailable.

AA6 stages independent browser generations. Gateway admission validates the full
immutable binding through the dedicated credential authority, including pending
operations; pending bindings never use public route lookup. A pending connector
installs only the correlated, fixed origin diagnostic handler. It cannot forward
arbitrary application traffic. Native desired-state refreshes independent browser
capability under the current rotating client certificate every two seconds.

The proxy claims at most eight readiness operations and runs fresh origin and
public probes in parallel under an eight-second probe budget. The same monotonic
ten-second round deadline covers immediate reporting; cached proofs are never
retried. Public DNS checks every answer, then dials a validated literal address
with registered SNI, system CA verification, no redirects and no environment
proxy. A cookie-free challenge binds the request and this proxy process through
hashed instance correlation. Challenge responses and origin metadata are bounded
to four KiB; public probes take at most five seconds. Pending-to-active polling
can cause a brief unavailable response while the connector replaces its
pending diagnostic handler with the authorized active forwarding handler.

`TestOwnedLocalProxyFixture` is a nonshipping, explicitly gated harness using the
fixed owned project/checkout and local certificate files. Its only public probe
exception maps the fixed payroll fixture hostname to literal loopback with the
owned CA. The normal executable has no corresponding trust or address bypass.
