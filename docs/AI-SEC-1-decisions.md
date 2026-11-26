# AI-SEC-1: close six gaps in AI Agents, MCP and AI Gateway

Status: implementation on `story/ai-sec-1` (local; not pushed).

## Problem

A full flow review of AI Agents, MCP and AI Gateway on main `6fbd6ffc` found
six places where the product is less safe than its own documentation says.
Each was confirmed in code before this paper was written.

1. **Agents inherit their owner's access.** `ruleMatchesDevice`
   (`policy/fqdn_forwards.go`) matches `user` and `group` rules against any
   device whose owner qualifies, including agent devices. A new agent silently
   gets everything the person who enrolled it can reach. Only the Kubernetes
   API is excluded. The docs describe an agent as a separate non-human
   principal.
2. **The MCP loopback proxy accepts any local caller.** `MCPToolProxyDynamic`
   (`apps/cli/internal/cli/mcp_proxy.go`) checks neither `Host` nor `Origin`.
   A web page open on the agent host can POST to `127.0.0.1:17100` and run
   allowed tools with the agent's OAuth token. The workload proxy
   (`workload.go`) already refuses such requests.
3. **MCP OAuth consent is not bound to the browser that started it.**
   `Complete` (`mcpoauth/service.go`) trusts the `state` value alone. An
   authorization link forwarded to someone else binds their upstream account
   to the agent.
4. **MCP OAuth state is wrong in two cases.** A token with no `expires_in` is
   stored with a NULL expiry and `Lease` then never returns it. A failed
   refresh leaves the connection `connected`, and there is no way to
   disconnect or reconnect.
5. **One switch opens HTTP for both the VPN and the public internet.**
   Members reach models over the automatic VPN path only when the server-wide
   "Allow AI Gateway over HTTP" is on, and that same switch permits plaintext
   on public AI paths that carry provider keys and workload tokens.
6. **Agent bootstrap tokens are invisible.** Issuing one writes no audit row,
   a live token cannot be listed or revoked, and the generated command puts
   the token into shell history.

## Decisions

- Locked: an agent device matches only `agent` and `agent_group` rules, the
  same model sandboxes already use. `user` and `group` rules no longer apply
  to agent devices.
  - This changes behaviour for existing installations: an agent that relied
    on its owner's rules loses that reach until a rule names it or one of its
    agent groups. A migration is not possible without guessing intent. The
    agent Access tab now states the rule and links to the agent's rules.
  - Deferred to AI-UX-1: a list of what each agent can reach, and a one-click
    "create rules from the owner's access" preview for agents left without a
    rule. Release notes must call the change out.
  - Rejected: keeping inheritance behind a per-organization toggle. It keeps
    the unsafe default alive and adds a setting customers must understand.
- Locked: the MCP proxy refuses a request unless `Host` is exactly its own
  loopback listener, no `Origin` header is present, and `Content-Type` is
  `application/json`. This is the workload proxy's rule. No new credential is
  introduced, so existing agent clients keep working.
  - Deferred: a per-runtime local bearer secret. It needs every MCP client
    configuration to change and is tracked for the UX story, where the proxy
    address is surfaced.
- Locked: starting OAuth consent sets an HttpOnly, Secure, SameSite=Lax cookie
  holding a random value whose hash is stored in the flow. The callback
  requires the cookie; without it the single-use flow is consumed, the
  connection is marked failed and the authorization code is never exchanged.
  The cookie is scoped to the callback path and lives ten minutes.
  - Not done: also requiring a signed-in session on the callback. The route is
    unauthenticated by contract and the cookie already proves the same
    browser, which is what the attack needs to defeat.
- Locked: a token response without `expires_in` is stored and leased as a
  non-expiring token. A refresh that the issuer rejects moves the connection
  to the existing `expired` state with a failure code (no schema change). A connection can be disconnected,
  and consent can be started again from `expired`, `failed` or `disconnected`.
  Connect, failure, re-consent and disconnect write audit rows.
- Locked: the transport policy gains a second field. "HTTP inside the VPN"
  covers only the gateway relay route and defaults to on; "public HTTP" keeps
  the existing field, meaning and default. An installation that had the old
  switch on keeps both on, so nothing stops working on upgrade.
- Locked: issuing a bootstrap token writes `agent.bootstrap_token_issued`.
  Pending tokens can be listed (name, gateway, issuer, expiry; never the
  value) and revoked, with `agent.bootstrap_token_revoked`. The generated
  command reads the token from a prompt instead of embedding it, so it never
  enters shell history.
- Rejected: one PR for security and experience work together. Experience
  changes (enable-in-place, enrollment status, approvals inbox, MCP's own
  switch, budgets for user groups, docs) follow as AI-UX-1.

## Validation

- Unit tests first for each item: policy compiler (agent device vs user and
  group rules, K8s API unchanged), MCP proxy (Host, Origin, Content-Type),
  OAuth (cookie and actor binding, NULL expiry lease, refresh failure state,
  disconnect, restart), transport middleware (relay vs public matrix, upgrade
  default), bootstrap token (audit, list, revoke, revoked token refused).
- `make generate-check` because the API contract changes.
- Changed Go packages in both editions, web unit suite, typecheck, build,
  gofmt.
- Security change: run the agents and MCP end-to-end specs locally.
