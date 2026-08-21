# F14 — MCP per-tool policy enforcement box-walk

## Local proof

- [x] The runtime protocol guard accepts both MCP `2025-11-25` and
  `2026-07-28` request forms.
- [x] A real proxy-stack test sends a body for `tools/call dangerous` with a
  forged `Mcp-Name: safe`; it returns 400 and the upstream invocation counter
  remains zero.
- [x] An allowed `tools/call safe` reaches the configured upstream only after a
  current policy projection permits it.
- [x] The API policy is immutable/versioned, inventory-bound, audited, and
  defaults to no rules. A stale inventory (more than one minute) yields an
  empty runtime allow-list.
- [x] A connected F13 OAuth credential is unsealed only for the exact runtime
  and upstream, refreshed server-side when needed, returned with `no-store`,
  and retained by the runtime only in memory.

## Live wire proof — completed 2026-08-21

Disposable CP: `54.79.53.95`; managed agent: `3.26.228.109`. The temporary
F14 proxy bound only to `127.0.0.1:17100` and used public, unauthenticated
DeepWiki at `https://mcp.deepwiki.com/mcp` (streamable HTTP,
`2025-11-25`). No private repository, client secret, OAuth token, or caller
authorization header was used.

1. The agent reported DeepWiki inventory: server `DeepWiki`, three tools, zero
   resources, and zero prompts. The CP UI displayed the inventory in shadow
   mode.
2. In **AI agents → MCP tool policy**, the operator selected only
   `DeepWiki · read_wiki_structure`. The UI showed policy version `1`; the CP
   audit log recorded `agent.mcp_tool_policy.replaced` with `rule_count: 1`.
3. A `tools/call read_wiki_structure` through `http://127.0.0.1:17100` returned
   HTTP `200` from DeepWiki. DeepWiki returned an ordinary public-repository
   lookup result (the selected repository was not indexed), proving the proxy
   forwarded the allowed request.
4. A `tools/call read_wiki_contents` through the same proxy returned HTTP `403`
   and `MCP tool is denied by policy`; it was rejected locally. A forged
   `Mcp-Name: read_wiki_structure` with a body requesting `read_wiki_contents`
   returned HTTP `400` and `MCP request headers do not match its body`.
5. The runtime policy projection returned an empty allow-list while inventory
   age exceeded one minute, then returned version `1` with the selected rule
   after the next fresh agent report. This proves the stale-inventory fail-closed
   gate. During the walk we also found and fixed the missing runtime-auth
   allowlist entries for the F14 policy and OAuth-lease routes; before that
   fix, the proxy safely denied a `401` policy fetch.
6. A direct, identical public DeepWiki call returned HTTP `200`, documenting
   the deliberate F14 boundary: only clients configured to use the explicit
   loopback proxy receive F14 enforcement. A public provider has no OAuth
   discovery, so the F13 token-lease path remains covered by its local
   contract tests; a protected OAuth provider is the named trigger for a
   separate wire proof.
