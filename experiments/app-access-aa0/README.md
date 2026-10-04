# AA-0b outbound transport spike (nonshipping)

This isolated Go module qualifies a candidate path, not product integration.
Gateway initiates TCP/TLS 1.3 mTLS and authenticated internal HTTP/1 CONNECT to
proxy. After acceptance the public proxy is HTTP client on that already-outbound
socket; connector serves HTTP on that socket and reaches its configured origin.
There is no public-to-gateway dial or inbound gateway listener. Browser CONNECT
is rejected. Each tunnel is one org/gateway/app/revision, one upstream connection;
no custom cryptography, multiplex framing, automatic retry or stream migration.

Proxy owns allowed binding. Verified certificate serial resolves through a
server-owned identity map to org/gateway; app/revision headers only match that
binding, never select authority. This is an abstract fixture for production's DB
lookup/revocation; adapt its decimal serial to production hex convention. Existing
CN/node names do not establish org identity. TLS issuer verification precedes map
lookup. Connector's origin comes from configuration, never browser input.

For HTTPS origins, proxy uses a logical HTTP connection over the TLS tunnel;
connector alone verifies origin HTTPS chain/hostname with default or explicit
private roots. No skip-verify switch. Production must additionally pin current
assignment/digest, validate DNS/destination ranges, strip control credentials and
cookies and renew stream authority leases. These are not implemented here.

## Run

From this directory with a complete maintained Go toolchain:

    go test -timeout 20s -count=1 -v ./...

Evidence environment: cached golang:1.26.8-alpine container, --network none,
loopback fixture services only. Host Go1.26.5 installation lacked stdlib source.

Tests exercise exact HTTP bytes through both proxies, reconnect with a new tunnel,
SSE delivery and origin cancellation, forged app/revision, wrong certificate
mapped org/gateway, capacity refusal, two masked WebSocket messages after upgrade and browser-close origin cancellation,
slow browser reader termination, HTTPS trusted root success/untrusted root denial.
WebSocket uses a minimal RFC6455 frame fixture, not a browser interoperability suite.

## Bounds and findings

Capacity fixture admits two live tunnels; rejects third with 503. Map entries and
slots release on close. Queued closed entries are skipped when consumed; no-demand
expired queue entries can still cause refusal until consumed (safe unavailable).
Each queued socket has a 5-second read/write deadline and forced close after 15
seconds; active tunnel has a 3-second absolute deadline in the stress fixture.
Connector CONNECT handshake has a 3-second deadline; headers 32KiB, response-header
wait 2 seconds. The public TLS listener must set TLS/header handshake deadlines in
production; httptest listener does not prove preauth capacity. Copy buffers are
stdlib streaming buffers, not body accumulation, but no measured RSS/load budget.

A tunnel deadline ALONE did not stop an origin when public ReverseProxy blocked
writing a nonreading browser. The bounded slow-reader test requires public listener
WriteTimeout=3s. Production SSE/WebSocket needs explicit per-write idle deadlines,
lease-based close and upload/download limits rather than a global 3-second cutoff.
No claim that current resource policies are suitable for shipping. Certificate
rotation, stale assignment refresh, initial dial queue wait, handshake DoS, HTTP2,
DNS rebinding, origin hostname mismatch and reconnect churn still need qualification.

## Fit decision and estimates

Candidate viable for single proxy/connector v1: maintained stdlib crypto/tls,
net/http, httputil. Prefer HTTP/1 tunnel baseline before H2 multiplexing because
std HTTP/1 hijack and ReverseProxy upgrade paths are exercised here. Cost: one TLS
connection per concurrent origin HTTP/WebSocket stream, gateway replenishes a
bounded ready pool. No load/capacity sizing or HA claim. AA-3/4 remain L; add explicit
pool lifecycle/backoff, certificate/assignment authority and protocol limit work
before production selection. This prototype does not finish AA-3/4 or AA-8.

Go source is BSD-style licensed; no added third-party dependency. Official security
review checked 2026-10-03: Go1.26.6 includes crypto/tls/net/http security fixes after
host1.26.5; cached1.26.8 includes those and1.26.7 net/http fixes. Review applicable
advisories again at shipping build; test success is not a vulnerability audit.
Sources: https://go.dev/doc/devel/release and https://go.dev/doc/install/source
and https://pkg.go.dev/net/http/httputil#ReverseProxy .

Module boundary: proposed production apps/app-proxy (independent binary/public
listener, approved-host routing, internal CP authority client, tunnel broker),
apps/node/internal/appaccess (outbound pool + exact-origin connector), and
apps/api/internal/appaccess (identity/registry/grants/revision/lease authority).
This experiments module is not imported by those modules and contains no API/schema.
Public write timeout is an explicit deployment prerequisite of the slow-reader
fixture, not automatic behavior of Broker.Proxy. Negative tests also cover unknown
serial, missing certificate, internal wrong method/path and browser CONNECT;
POST request/response byte equality covers a small upload/download. Continuous pool
idle expiry/reconnect churn, upload cancellation remain
separate acceptance work; no bounded RSS claim is made.
