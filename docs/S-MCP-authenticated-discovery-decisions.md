# MCP authenticated connections and tool discovery

Status: locked by the user on 2026-09-09: "do as recommended".
Inspected against `ai-improvement` content at `b33e2177` on 2026-09-09.
The user approved implementing the recommended shared service-credential and
automatic discovery flow. Local fixtures and isolated schema verification are
part of this implementation; no real credential, fleet, or network change is required.

## Requested outcome

The user wants to add an MCP server, authenticate when needed, automatically see
the tools that identity can list, and grant agents access to selected tools.
Creating a connection must not automatically authorize tool execution.

## Current implementation, verified from source

- `apps/web/src/pages/AgentsMCP.tsx` sends only name and endpoint to profile
  creation. The profile schema has no authentication or inventory fields.
- F19 D6 makes profiles shared configuration, explicitly not shared credentials.
  Existing assignments select one active upstream per agent through Agent Groups.
- F12 and F13 keep discovery on the managed runtime. The control plane does not
  connect to MCP servers for discovery. Inventory belongs to an agent.
- OAuth is available on the agent detail page after protected-resource discovery.
  `AgentMCPOAuthPanel` asks for a pre-registered client ID, optional client secret,
  and scopes. Tokens are sealed by `mcpoauth.Service` and leased to that agent.
  There is no profile-level API-key/Bearer credential lifecycle.
- `managedRuntimeSource.Report` calls `ObserveMCPInventory` without the OAuth
  lease. `mcpSessionRequest` has no Authorization input. Successful OAuth consent
  therefore does not authenticate this collector's initialize/list requests.
- `observeMCPEndpoint` sends one request for each list and ignores `nextCursor`.
  A later-page tool is missing. List failures can still produce a healthy
  normalized observation, contrary to the F19 D4 usable-inventory requirement.
- `MCPProxyAuthorization` caches a token by expiry without an endpoint cache key.
  Endpoint binding must be preserved when sharing this path with discovery or
  replacing the active profile; credentials must never cross upstreams.
- Existing per-agent tool policy validates names and schema hashes against
  observed inventory, then filters runtime grants against fresh observations.
  A catalog preview must not be substituted silently for this enforcement proof.

## Approved decision

The missing form controls span credential ownership and network execution, not
just presentation. A profile-level shared connection changes F19 D6 and central
discovery changes F12/F13's runtime-only collector boundary.

Locked: an explicitly shared MCP service connection owned by the profile.
Its credential can be used only for that exact endpoint by assigned agents in
the same organization. Ordinary users/agents cannot read it through management
APIs. Existing per-agent OAuth connections remain separate and are not silently
promoted into a shared identity. A profile has an explicit auth mode; never fall
back from a failed shared credential to a different identity.

For public endpoints, discover from the control plane using validated outbound
requests. For private endpoints, select a reachable managed agent as the discovery
runner. Do not automatically enable a runtime, publish a port, or alter routes.
An unreachable endpoint remains a visible network failure, not an empty catalog.
This adds a profile catalog; per-agent fresh observation remains required for
the existing runtime policy projection.

Alternative: retain per-agent credentials and runtime-only discovery, expose
that setup clearly in MCP, and collect tools after selecting/connecting an agent.
This has less architectural change but cannot provide a shared authenticated
catalog immediately on adding a server without a discovery agent.

Disposition: shared profile credentials and public-control-plane/private-agent
discovery approved. The per-agent-only alternative is rejected because it does
not deliver the requested shared onboarding flow. Existing connections remain
legacy per-agent until explicitly configured as a shared profile connection.

## Locked user flow

1. Add server name and endpoint. Choose No authentication, Bearer/API key, or
   OAuth. Credential fields are conditional; secrets never go into endpoint URLs.
2. Connect and discover. OAuth uses consent, with registered-client fields when
   required; it is not a generic password field. Report Connecting, Sign-in
   required, Connected, Unauthorized, Network failure, or Incomplete discovery.
3. Once authenticated, initialize, send the initialized notification, and fetch
   every `tools/list` page within explicit resource/time bounds. Keep session and
   negotiated protocol headers consistent. Refresh after connecting and offer a
   retry/refresh action. Never invoke tools during discovery.
4. Show searchable tool names, descriptions and schemas. These are the tools
   visible to the authenticated identity, not a claim of every tool on the server.
   Partial pagination or a failed list is visibly incomplete and grants no access.
5. Select an assigned agent and its allowed tools using the existing policy
   controls. New or changed tools are visible for review and default denied.
   Assignment alone grants no tools. Keep group profile assignment and per-agent
   execution scopes explicit until group tool-policy inheritance is separately
   designed.
6. Rotate/disconnect credentials and refresh status from this workspace. Explain
   that a shared connection change affects its assigned agents. Preserve existing
   assignment history and archive refusal while the profile is assigned.

## Implementation and verification

- Record the chosen identity/discovery model here before product code. Define
  OpenAPI requests, responses, named permissions, sealed storage, disconnect and
  rotation transitions before generating Go/TS/sqlc/RBAC artifacts.
- Reuse normalization, schema hashes, crypto sealing, OAuth PKCE, managed runtime
  transport and tool-policy enforcement. Avoid a second tool authorization system.
- Test public and authenticated servers, OAuth discovery/consent, multi-page
  tools, empty catalogs, incomplete/failed later pages, repeated cursors, session
  handling, redirect refusal, endpoint replacement, credential rotation,
  cross-organization access and secret-free responses/audits.
- Prove that a selected tool can execute through the managed proxy and an
  unselected/new/changed tool cannot. Revoke access and verify subsequent refusal.
- Render the create/connect/tools/grant/error states in the existing shared theme.
  Use labeled local fixtures and isolated databases for the walkthrough; do not
  treat unit tests as live-wire proof.
- Update the core and website MCP guides after implemented behavior is verified.

## Protocol references

- [MCP HTTP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  specifies OAuth discovery and authenticated HTTP requests; authentication is
  optional for public servers.
- [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
  specifies paginated `tools/list` and tool-list change notifications.

## Implementation decisions within the approved flow

- A small standard-library Go module under `packages/mcp` shares the existing
  inventory normalization and the repaired collector between API and runtime.
  It owns protocol/pagination only; callers own credential and network policy.
- New named MCP connection read/manage permissions protect shared secrets and
  discovery. Existing profile edition/organization opt-in continues to apply.
- Connection configuration is separate from immutable profile identity. Changing
  authentication or runner increments a revision and invalidates inventory and
  pending OAuth transactions. Disconnect clears credentials; archive keeps the
  existing active-assignment refusal. Secrets never appear in list/detail APIs.
- A selected private discovery runner gets only explicitly assigned discovery
  jobs for its organization through machine-authenticated endpoints. A discovery
  job is not a tool execution grant. Results must match profile, runner and
  revision. Runtime execution leases additionally require active group assignment.
- Shared OAuth reuses the registered-client/PKCE/token-sealing implementation;
  it has profile ownership distinct from per-agent OAuth. No dynamic client
  registration or new grant type is introduced.
- Tool lists are bounded at 1024 entries, 64 pages and 512 KiB normalized output;
  timeouts, repeated cursors, malformed replies and exceeded bounds are errors,
  not truncated success. Discovery never calls tools.
- No changes to network routes or runtime opt-ins are implicit in connecting.
  Private discovery needs an already reachable, enabled managed runtime.
