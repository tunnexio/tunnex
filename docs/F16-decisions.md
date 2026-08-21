# F16 — Argument controls, rate limits, and step-up approval

## Decision

F16 extends F14's existing loopback-only HTTP MCP proxy. It makes a decision
only for a validated `tools/call` request that already matches a current,
inventory-pinned F14 allow. Direct upstream use, stdio, response inspection,
prompt-injection detection, and OAuth consent changes remain outside this
story.

The proxy continues to treat the JSON-RPC body as authoritative. F16 reads
only `params.arguments` long enough to validate and forward it; arguments,
results, OAuth material, and approval secrets are never persisted in audit
records or returned to ordinary API/UI reads.

Current MCP guidance supports this narrow host boundary: tool inputs must be
validated, and hosts should provide approval controls, rate limiting, and
bounded tool loops. The protocol does not prescribe a central policy format,
so Tunnex retains a server-owned, versioned policy rather than interpreting
provider descriptions as authorization.

Sources consulted:

- [MCP tools](https://modelcontextprotocol.io/specification/draft/server/tools)
- [MCP sampling security considerations](https://modelcontextprotocol.io/specification/draft/client/sampling)
- [MCP authorization (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

## D1 — F14 proxy is the sole enforcement point

F14 already ships `tunnex-agent-runtime`'s explicit loopback HTTP proxy. F16
adds checks to that handler after its protocol/header integrity guard and
before its authorization lease or upstream round-trip. A refusal therefore
does not contact the upstream.

The proxy binds only to a configured loopback address and has one
server-owned upstream. F16 must never add transparent interception, a remote
listener, a client-selected target, or a permissive fallback if policy lookup
is unavailable.

## D2 — Bounded constraint profile, not arbitrary JSON Schema execution

Each exact F14 tool identity may have one optional argument-control profile.
The profile is a finite, server-validated subset of JSON Schema for a JSON
object: `required`, per-property `type`, scalar `enum`, string `maxLength`,
number `minimum`/`maximum`, and `additionalProperties: false`. It rejects
arrays, nested objects, pattern/format evaluation, schema references, and
unbounded provider-supplied schemas. An absent profile preserves F14's
per-tool allow decision; a present profile must match before the call passes.

This is intentionally a policy-authored restriction, not validation against a
tool's advertised input schema. F12's schema hash continues to pin the tool
shape; F16 constrains a tenant's allowed values within that shape.

## D3 — Local fixed-window rate limit

Each allowed tool may specify an optional positive maximum calls per minute.
The local proxy enforces the counter in memory, keyed by current policy
version and exact inventory identity. A runtime restart resets counters, which
may make limits temporarily less strict but never turns a denied tool into an
allowed one. CP unavailability leaves the last successfully fetched policy in
place only until its existing freshness window expires; after that the proxy
fails closed.

Distributed quota and billing are explicitly deferred: the current topology
has one local proxy per managed agent, and pretending a local counter is an
organization-wide quota would be dishonest.

## D4 — Step-up approval is a one-use CP capability

A tool profile can be classified `step_up_required`. When such a call passes
the F14 allow and argument profile, the proxy creates a bounded pending
request with only the exact catalog identity, a redacted argument summary, and
an expiry. It does not forward the request. An authorized operator may approve
or deny it in the agent UI. Approval creates a short-lived, one-use permit
bound to the agent, policy version, tool identity, and request digest. The
runtime exchanges that permit immediately; a replay, changed argument body,
expired permit, stale policy, or denied request is refused before upstream.

The browser never receives a bearer credential or raw argument body. The
runtime receives only the result necessary to continue the in-flight local
request. Both requester and approver actions are audit events with bounded
metadata.

## D5 — Separate authority and visible state

F16 adds distinct RBAC permissions for configuring argument controls and for
approving step-up requests. The existing F14 policy permission is not reused:
editing a standing tool allow and approving a particular destructive invocation
are separate authority planes. Owners receive both; administrators receive the
approval permission; members cannot self-approve.

The agent page shows, for each inventory-pinned tool, its constraint profile,
local rate cap, and whether a human approval is required. It also shows a
bounded pending/approved/denied/expired approval history. It never shows raw
arguments, tool results, access tokens, client secrets, or approval permits.

## Slices

1. **Policy contract:** extend immutable F14 rule versions with the bounded
   constraint/rate/step-up fields, generated API, RBAC, and safe projections.
2. **Local enforcement:** validate `params.arguments` and apply per-tool rate
   limits in the existing proxy before it can obtain an OAuth lease or reach
   upstream.
3. **Approval state machine:** pending/approved/denied/expired one-use permits
   and runtime-mediated exchange, with audit records and no argument storage.
4. **Operator surface and walk:** configuration and approval queue, plus local
   proxy proof for valid/refused/rate-limited/approved/replayed paths.

## Non-goals and stop conditions

- No arbitrary JSON Schema evaluator, arrays/nested values, response controls,
  prompt-injection detection, stdio, direct-upstream enforcement, distributed
  global quota, provider-specific destructive-action inference, or OAuth
  change.
- If a requested restriction needs fields outside the bounded profile, reject
  it rather than silently ignoring it.
- If the runtime cannot bind an approval permit to the exact request digest,
  stop; a generic approve-once flag is not safe.
- F16 is not complete until a real proxy test proves refusal happens before the
  upstream handler observes the call.
