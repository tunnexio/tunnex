# F14 — MCP per-tool policy enforcement

## Decision

F14 adds a second, HTTP-only enforcement plane for MCP tool calls.  It is not
an extension of Tunnex's WireGuard/nftables policy compiler: those controls
continue to be the outer L3/L4 fail-closed boundary, while F14 is a managed
agent-host reverse proxy that parses a bounded MCP request before it forwards
it.  The proxy is explicit and loopback-only; an MCP client must be configured
to use its local Tunnex endpoint.  A server that the client reaches directly is
outside F14's tool boundary and must never be shown as enforced.

This is deliberately the smallest useful L7 boundary.  It does not claim to
detect prompt injection, inspect intent, host a model, proxy stdio, or turn a
catalog view into authorization.

## Evidence and compatibility baseline

F12 already gives F14 a bounded, secret-free, agent-local catalog: configured
endpoint, reported server name, tool name, and input-schema hash.  F13 binds a
sealed OAuth credential to an observed protected resource but deliberately
does not hand it to the runtime.  The managed runtime currently only polls and
reports; it is not in the MCP data path.  Therefore the proxy and a narrowly
scoped credential handoff are required for a real tool decision.

The supported HTTP revisions are MCP 2025-11-25 and 2026-07-28.  The former
may use the initialize/session flow; the latter is stateless and carries
`Mcp-Method` and `Mcp-Name` headers.  Stdio is out of scope: it is a local
child-process channel with no network boundary for Tunnex to intercept.

Sources consulted during this decision:

- [MCP Streamable HTTP transport (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP authorization (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP security best practices (2026-07-28)](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx)

## D1 — Explicit local proxy, never transparent interception

Each protected MCP endpoint has a local proxy URL on the managed-agent host.
The listener binds only to `127.0.0.1`; it is not exposed through WireGuard,
the gateway, or an ingress.  The operator configures the colocated MCP client
to use that local URL.  The proxy knows the one upstream endpoint from its
server-owned runtime configuration and refuses a Host/header/request target
that attempts to choose another one.

This is a deliberate trade-off: it protects colocated HTTP clients, and does
not claim to protect a client that bypasses it.  A transparent redirect would
be less honest, harder to roll back, and cannot reliably distinguish MCP from
other HTTPS traffic without terminating all of it.

## D2 — The JSON-RPC body is authoritative

F14 accepts only a single bounded JSON-RPC object over HTTP POST.  It parses
the body before policy lookup.  For `tools/call`, `params.name` must be a
non-empty string and is the sole tool identity used for authorization.

For 2026-07-28 requests, `Mcp-Method` must equal the parsed JSON-RPC method;
for `tools/call`, `Mcp-Name` must equal `params.name`.  For 2025-11-25,
headers are optional, but if supplied they must also match.  A missing required
header, malformed/oversized/batched body, or header/body mismatch returns a
local JSON-RPC error and is never forwarded.  Headers are an integrity check
and routing hint, never an authorization claim.

The first stack-level red must demonstrate that a request whose headers name an
allowed tool but whose body calls another tool is rejected before an upstream
handler can observe it.

## D3 — Stable catalog identity and schema pin

A policy target is the F12 agent-scoped server identity:

```
canonical endpoint + reported server_name + tool name + input_schema_hash
```

The endpoint and server name select the observed server; the tool name selects
the capability; the schema hash prevents an existing allow from silently
covering changed arguments.  Display names/descriptions are not identities.
An unknown endpoint, server, tool, missing schema hash, stale inventory, or a
changed schema has no matching allow and is denied.  Operators re-allow the
new observed hash intentionally.

## D4 — Versioned default-deny policy

Policy records are organization and managed-agent scoped, versioned on every
mutation, and immutable as historical rows.  The effective view contains only
the latest enabled allow entries.  There is no broad "allow this server" and
no active deny rule: absence is the closed state.  New discovery is therefore
safe by default.

F14's first UI is a server-to-tool selection built only from the last valid F12
snapshot.  It clearly marks unselected, newly changed, unavailable, and
enforced-via-local-proxy states.  It does not promise that a tool list is
filtered; `tools/list` is presentation only.  The `tools/call` check remains
the enforcement decision even when a client calls an unlisted name directly.

## D5 — Credential use is an explicit, bounded runtime handoff

F13's sealed token is not returned by any ordinary API/UI read.  F14 adds one
agent-runtime-authenticated lease operation for a *connected*, unexpired
connection whose canonical protected resource exactly matches the proxy's
configured upstream.  It returns token material only to the local runtime,
only in process memory, and never to its state/config files, reports, logs,
audit metadata, or browser.  It has a short TTL and a one-endpoint audience.

Refresh-token renewal is attempted only by the CP, while the token remains in
the sealed F13 store.  If renewal, lease, inventory, policy read, or upstream
authorization fails, the proxy fails closed for `tools/call`; it does not fall
back to a caller-supplied bearer token or direct passthrough.

## D6 — Auditable outcome without MCP content retention

Every allow/deny/error decision produces a bounded audit event containing the
agent, catalog identity, policy version, outcome code, and request identifier.
Tool arguments, tool results, OAuth values, JSON-RPC IDs, and arbitrary request
or response bodies are not retained.  The audit record answers which boundary
decision occurred, not what private content a tool processed.

## Slices

1. **Pure protocol guard:** bounded single-request parser and header/body
   consistency validator, with the real-stack mismatch red and both supported
   HTTP revisions.
2. **Policy source of truth:** versioned catalog-pinned allow rows, generated
   API/RBAC, and a default-deny evaluator.
3. **Runtime boundary:** loopback reverse proxy, server-owned upstream binding,
   CP credential lease/refresh, and decision audit.
4. **Operator surface and walk:** observed server-to-tool selection, truthful
   status, direct-call bypass contrast, allow/deny/change/revocation wire proof.

## Non-goals and stop conditions

- No stdio interception, transparent redirect, remote listener, dynamic
  client registration, token passthrough, argument-level policy, response-body
  inspection, or prompt-injection detection.
- No support claim for MCP revisions other than the two HTTP revisions above.
- If a required provider only supports a transport or request shape that the
  bounded parser cannot validate, stop and add no permissive forwarding path.
- If colocating the MCP client with the managed runtime is not viable for the
  intended deployment, stop before proxy rollout; a different placement is an
  architecture decision, not a flag.

## Acceptance

- A policy-free/unknown/changed tool call is rejected before the upstream sees
  it; one exact observed, enabled, schema-pinned allow reaches the upstream.
- A header/body mismatch cannot reach the upstream even if its headers name an
  allowed tool.
- A direct upstream call remains visibly outside F14; a client using the local
  proxy receives the correct allow/deny result.
- OAuth material remains sealed at rest and absent from every browser/API
  projection, runtime file, report, log, and audit payload.
- Existing L3/L4 access remains required; F14 neither broadens nor replaces it.
