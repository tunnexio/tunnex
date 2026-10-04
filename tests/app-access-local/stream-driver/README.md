# Owned protocol termination driver

This nonshipping driver opens actual app-proxy requests through the fixed owned
payroll hostname, verifies TLS with the owned CA, and sends a separately minted
app session cookie on every request. It never mutates CP/Redis authority and uses
no push notification. A named trigger is qualified only alongside retained
actual API/Redis mutation evidence supplied by the orchestrator.

Build with the pinned Go toolchain, without changing shipping runtime artifacts:

```sh
GO111MODULE=off go build -o /private/tmp/aa7-stream-driver tests/app-access-local/stream-driver/main.go
```

Create a private, mode-0600 JSON file inside the owned `.runtime` directory with
one `app_session_token` property obtained from the real launch/redemption flow.
Do not print that file or put the token on a command line. Start the driver with
its absolute path:

```sh
APP_ACCESS_OWNED_PROJECT=tunnex-app-access-aa0-1003 \
APP_ACCESS_OWNED_CHECKOUT=/Users/pawangupta/tunnex/tests/app-access-local \
/private/tmp/aa7-stream-driver \
  --session-file /Users/pawangupta/tunnex/tests/app-access-local/.runtime/aa7-session.json
```

The origin must expose `/events`, `/ws`, `/long-response`, `/download`, and
`/upload`. Readiness requires initial positive traffic for all five protocols:
SSE content, RFC6455 handshake and frame, ordinary long HTTP content, known-length
download content, and upload `100 Continue`. The download then deliberately stops
reading to create backpressure; upload sends paced bytes against a known 64 MiB
length. All connections are independent and use the actual app session.

After `state:ready`, perform the actual trigger and send one JSON line on stdin
within one second of its completion. Include `trigger`, `mutation_started_at`,
`mutation_completed_at` (RFC3339Nano timestamps from the same host), and
`evidence_ref` identifying retained mutation evidence. The mutation must finish
within eight seconds of the marker; the marker must arrive within ten seconds of
stream readiness. These guards prevent expired streams or delayed markers from
being mislabeled as timely revocation.

The eight-second marker allowance accommodates a real disable response that
waits five seconds for withdrawal confirmation. It does not extend the measured
five-second closure bound. A paused download only exposes closure when drained;
delayed markers can conservatively fail that observation rather than establish
an earlier socket-close time that the client did not observe.

For a mutation whose API response waits for withdrawal confirmation, the
orchestrator may first write one JSON line with `phase:"mutation_started"` and
`mutation_started_at` from the exact request event immediately before sending
that request. It must arrive after readiness and within one second of that start.
This releases the paused download to drain while the API waits, allowing actual
closure to be timestamped before the final response. The final marker must carry
the identical start timestamp, real completion and retained evidence reference;
the ten-second overall marker window and five-second closure bound stay fixed.
The slow reader is paused until mutation start, not indefinitely afterward.

The driver translates marker timestamps onto its monotonic clock. A passing
stream closes no later than five seconds after mutation **start**, a conservative
boundary earlier than commit, and did not close before the mutation. This can
fail conservatively for a slow mutation even if commit-to-close timing passes;
retain both start/completion timings. It also sends a new app request and requires
a generic denial or the exact safe session restart. Forced cleanup does not count
as an observed authority closure. Exit status is zero only for a complete passing
measurement, one for a failed measurement, and two for setup/marker refusal.

Already delivered bytes, buffered client data, and mutations accepted by the
origin cannot be erased. Download buffers are drained after the marker to observe
actual connection closure. Upload byte counts are bytes sent, not proof of a
committed application mutation. This driver alone cannot establish that the
named CP/Redis trigger occurred; correlate its output with authoritative evidence.

Only the exact owned triggers `gateway_pause`, `gateway_stop`, `cp_pause`, `redis_pause` and
`proxy_shutdown` may qualify a fresh request's timeout/refusal/reset/EOF as
transport unavailability. The output reports this separately from an HTTP 403 or
safe session restart. Keep the outage in effect until this phase finishes.
Revocation triggers retain the strict HTTP denial requirement. A proxy restart
is two phases: run `proxy_shutdown` while down, then independently record recovery
with a fresh authorized request after restart. A retained eligible app session
may legitimately work again; that recovery must not be labeled a denial.

The exact `grant-expiry` trigger measures a configured fixed deadline rather than
a revocation mutation. Its marker must include `persisted_expires_at` read back
from the authoritative grant, exactly equal to `mutation_started_at`. All five
streams must have positive origin traffic before that deadline. An observed
closure after positive readiness and by expiry plus five seconds qualifies,
including conservative early lease closure; retain negative relative times
without shifting the deadline. The orchestrator must establish that no competing
authority mutation occurred. Revocation still requires closure after mutation
start. This distinguishes loss of availability before expiry from continued
delivery after the expiry bound; it does not promise service through the last
millisecond of a grant.

The origin fixture exposes aggregate active counters at
`/__fixture/stream-state`; these contain no application/user/session identifiers.
Parent-owned runtime orchestration decides when to upgrade that fixture. Its
existing TLS CA/leaf keys were generated in memory, so the old private identity
cannot be recovered from its public CA file on an initial restart. Preserve the
running process or explicitly review a replacement fixture CA before HTTPS use.

## Capacity qualification plan

Run this only after the serial withdrawal matrix and after the orchestrator
confirms an active published revision, a fresh eligible session, and no concurrent
authority mutation. Use the same fixed hostname, owned CA, literal local dial and
private session-file boundary as the protocol driver. Preserve all native
enrollment identities and production TLS validation.

The first bounded native experiment will open sixteen independently authenticated
SSE requests for one session, requiring initial origin content on each. Continue
reading those streams so this experiment measures admission rather than a slow
reader. Request seventeen must receive the generic 403 without origin content.
Close one admitted client, then require a replacement to obtain initial origin
content within ten seconds. Finally close every test client and require a normal
root request to succeed. Cap the experiment at seventeen concurrent clients and
thirty seconds; failed setup immediately closes all owned clients. Retain only
counts, status codes, monotonic timing and source/artifact identifiers.

This qualifies the actual per-session sixteen-request bound and capacity release
on this owned application. It does not prove the app32, gateway128, global256,
callback128 or pending-channel128 bounds, which have focused implementation tests
but require separate native experiments to claim runtime qualification. It does
not measure a memory ceiling, throughput, multi-tenant fairness or HA. The fixture
does not expose a private metrics listener, so avoid pretending that a client-side
403 distinguishes every internal rejection cause: successful sixteen-stream
setup, the unchanged authority snapshot, and successful replacement are necessary
corroborating evidence. Slow-reader and blocked-upload behavior belongs to the
separate protocol matrix; delivered bytes cannot be recalled.
