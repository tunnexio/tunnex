# AA-0 local development evidence

Status: complete for AA-0 local architecture/contract acceptance. This record is
local development evidence, not release qualification.

## Baseline and ownership

Development began 2026-10-03 from refreshed `origin/main`
`bcf602770c54446b35a2f83bfa639e9f2a9a10c8`. The planning commit was not
present on main. Local branch `feature/app-access` carries that reviewed planning
commit as `5c1093e87db358cab06080cc272321a2e074802f`.

Work is split across three agents with disjoint ownership: authority contract
(`docs/AA-0-authority-contract.md`), transport spike
(`experiments/app-access-aa0/`), and real control-plane/gateway harness
(`tests/app-access-local/`). The integration owner reviews their combined result,
owns this record and epic/index updates, and controls progression to AA-1.

All implementation and evidence remain local. No remote branch publication,
PR update, deployment or CI watcher is authorized. The unrelated untracked
`apps/ai-bridge/` and `apps/ai-proxy/` directories and five existing stashes were
preserved. Existing Docker projects are outside the harness ownership boundary.

## Baseline corrections

The current runtime licensing source is
`apps/api/internal/licence/entitlements.go`: one binary, named feature sets
per runtime tier. Groups and the existing Zero Trust engine are Community
capabilities. The epic's older enterprise-group assumption must not guide
implementation. App Access needs its own named entitlement and organization
opt-in; existing group availability remains authoritative.

## Acceptance boundaries

AA-0a must supply a reviewed authority/API/UX contract. AA-0b must exercise
approved bytes through an outbound gateway-to-proxy path, forged stream refusal,
HTTP/SSE/WebSocket behavior, cancellation, reconnect and resource bounds.
The real local API and enrolled gateway must run together against owned
PostgreSQL/Redis dependencies. A standalone transport fixture does not prove
product login, publication, app sessions or integrated revocation.

No dependent product story is complete until its own integration and review
passes. Existing login MFA is preserved; per-app MFA remains AA-9.

## Local control-plane/gateway results

Central readback on 2026-10-03 confirmed API `/healthz` status `ok`, gateway
`/readyz` status `ready`, database/user `aa0|aa0`, and migration `166|false`.
The enrolled node is an active gateway with advancing heartbeat and
`egress_nat=true`; `ai_vpn_http_ready=false`. All four services carry Compose
project label `tunnex-app-access-aa0-1003`, join only its default network, and use
its named database/Redis/API/gateway volumes. Database and Redis have no host
ports. See [harness](../tests/app-access-local/README.md).

The real gateway uses the current binary with a cached networking-tool runtime,
WireGuard and NET_ADMIN confined to its own container namespace. An initial
memory-backend attempt enrolled but failed startup; the final harness does not
bypass the readiness requirements. The agent observed identity retention and
heartbeat advancement across an owned gateway restart. Independent review asked
for automated identity assertions, a local-daemon guard and checkout ownership
checks. Those changes are implemented: the harness pins the local Colima Unix
socket, verifies resource/checkout ownership, asserts current gateway/database
state and compares node ID, certificate serial and key fingerprint across an
owned restart. The agent's automated reconnect passed; central verification of
the corrected harness also passed.

## Transport review

The candidate uses maintained Go standard-library TLS and HTTP/1 CONNECT,
initiated by the connector. The public proxy sends HTTP over the accepted socket;
the connector alone reaches and verifies the registered HTTP/HTTPS origin.
Identity is a server-owned certificate-serial mapping, matching existing gateway
authority rather than trusting node name or fabricated certificate org fields.
See [spike](../experiments/app-access-aa0/README.md).

Initial central review found and the agent corrected tunnel map retention,
premature WebSocket closure and incorrectly nesting origin TLS at the public
proxy. Central verification of the final nine-test suite passed in a cached
offline Go 1.26.8 Alpine container (`3.952s`); the same final module passed native
cached Go 1.26.8 race instrumentation (`6.373s`). Alpine's cached toolchain lacks
the C compiler needed for race instrumentation, so the native cached toolchain
was used for that check. Slow-reader proof
requires the public listener's write timeout; a tunnel deadline alone failed to
terminate the origin. Fixed three-second stress deadlines are not renewable
leases or sustained-stream proof. No measured memory/load/capacity claim follows
from these fixtures. Final tests exercise unknown serial, missing certificate,
public CONNECT and invalid internal method/path refusals, POST byte equality,
and WebSocket cancellation reaching the origin.

## Accepted decision and next story

Independent re-review found no remaining AA-0 blocking findings. Select the
conditional maintained Go stdlib mTLS/HTTP/1 outbound CONNECT baseline described
in the spike. AA-3 and AA-4 must implement bounded pool lifecycle, destination
restrictions, service-purpose authorization, renewable leases and sustained
protocol/resource qualification; the spike is not production code to copy blindly.
Connector/proxy story sizes remain L, with those tasks explicitly included.

AA-1 starts next: OpenAPI-first tenant-safe registry/revisions, named runtime
entitlement and opt-in, named permissions/generated mirror, audited optimistic
draft CRUD and admin inventory. Publication is not enabled by draft CRUD.
