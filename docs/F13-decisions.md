# F13 — MCP OAuth and protected-resource trust

## Decision

F13 establishes a trusted OAuth connection for one observed MCP server in
preparation for F14. It discovers and validates authorization metadata, obtains
user consent through the Tunnex control plane, and stores the resulting token
material sealed at rest. It does not proxy MCP traffic, call a tool, read a
resource, apply an allow/deny decision, or expose a token to the browser.

## D1 — Discovery remains agent-side

The managed agent already reaches the configured MCP endpoint; the control
plane does not. The runtime discovers OAuth Protected Resource Metadata (PRM)
from a `401` `WWW-Authenticate` challenge when present, otherwise by RFC 9728
well-known paths. It reports only bounded metadata through its existing
authenticated channel: canonical protected-resource URI, allowed authorization
server issuer URLs, supported scopes, and a stable discovery status. It never
reports response bodies outside that allow-list or an authorization header.

## D2 — Pre-registered OAuth client only

F13 accepts an operator-supplied client ID and optional client secret for the
selected authorization server. The client secret is sealed under Tunnex's
existing master key and is never returned. Dynamic client registration and
Client ID Metadata Documents are deferred: both add remote registration or
hosted-metadata lifecycle that is not needed for the first reliable connection.

## D3 — Authorization code with PKCE

The browser is redirected to the discovered authorization endpoint. The CP
creates a short-lived, single-use authorization transaction with a PKCE
verifier, exact callback URL, selected protected resource, issuer, scopes, and
CSRF state. The callback exchanges the code with the `resource` parameter.
The browser receives only terminal connection state, never code, verifier,
access token, refresh token, or client secret.

## D4 — Resource and issuer binding is fail-closed

The connection records the canonical protected-resource URI from PRM and the
selected issuer. The issuer must be present in PRM `authorization_servers`; if
authorization-server metadata enumerates `protected_resources`, it must include
the same canonical resource. The authorization and token requests both carry
that canonical URI as the RFC 8707 `resource` value. Opaque tokens are not
parsed or guessed; their audience binding is established by the resource-bound
OAuth exchange.

## D5 — Token custody is sealed and non-transitive

Access and refresh tokens live only in a dedicated sealed-credential table,
scoped to organization, agent, observed MCP server, issuer, and canonical
resource. API list/detail responses show a keyed fingerprint and expiry/status
only. Runtime reports, managed-agent configuration, audit payloads, browser
redirects, logs, and URL query strings never contain token material. F14 must
add an explicit short-lived runtime handoff before any MCP request can use a
stored credential.

## D6 — Authority and UX

`agent:manage` starts or disconnects an OAuth connection; `agent:view_privileged`
may see secret-free trust metadata and connection status. The wizard shows the
discovered protected resource, issuer, requested scopes, client registration
mode, consent state, and terminal result. Absence, pending consent, failure,
and expired credentials are distinct; no state is portrayed as authorized MCP
tool access.

## Non-goals and deferred decisions

- Dynamic client registration and Client ID Metadata Documents (defer to a
  compatibility follow-up when a concrete provider requires either).
- Device/client-credentials grants, token exchange, token passthrough, and
  agent token handoff (F14+).
- Tool/resource/prompt policy and enforcement (F14).
- Human/workflow provenance and step-up approval (F15/F16).

## Acceptance

- Current and legacy-compatible PRM discovery reports only allow-listed facts.
- Cross-org, wrong-agent, unknown issuer, callback replay, expired transaction,
  redirect mismatch, and resource mismatch all refuse without leaking state.
- Client secrets, codes, PKCE verifier, access tokens, and refresh tokens are
  sealed or ephemeral and absent from all readable API/UI/log surfaces.
- A rendered wizard performs discovery, scoped consent start, callback result,
  and secret-free connection status.
