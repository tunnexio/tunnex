# F12 — MCP server and tool inventory in shadow mode

## Decision

F12 observes MCP inventory only. It neither proxies MCP traffic nor executes a
tool, reads a resource, resolves OAuth metadata, stores an access token, or
changes any network policy. Those decisions remain F13+.

The managed runtime is the only collector. It performs the MCP `initialize`
handshake and paginated `tools/list`, `resources/list`,
`resources/templates/list`, and `prompts/list` calls against an explicitly
configured endpoint, then reports a bounded normalized snapshot through its
existing authenticated runtime channel. The control plane never dials an MCP
server itself.

## Compatibility

The collector accepts negotiated protocol versions `2024-11-05`,
`2025-03-26`, `2025-06-18`, and `2025-11-25`. It records the negotiated
version, advertised capabilities, transport, latency, and a bounded stable
error code. Unknown future versions are reported as `unsupported_version`; no
partial inventory is trusted.

Legacy HTTP+SSE and current Streamable HTTP are collector transports. stdio is
not collected: it requires process ownership and has no remote trust boundary.
The normalized inventory preserves modern optional metadata (title, icons,
output schema and list-change capabilities) while remaining valid for legacy
servers that only provide the original list entries.

## Stored truth and bounds

Each server is scoped to its managed-agent device. Server identity is an
operator-configured endpoint identity plus the reported server name; F14 must
use the stored server/tool IDs, never a display label. We retain only metadata:
names, descriptions, URI/template identifiers, schema hashes, bounded schema
JSON, protocol/capability facts, duration, and first/last seen timestamps.
Resource contents, prompt messages, tool results, authorization headers,
session IDs, and credentials are rejected before persistence.

Every report replaces the inventory for that exact agent/server atomically.
Missing items are marked absent rather than deleted, preserving a changed/new
view. Health is derived from the last observation; there is no control-plane
probe. A stale/missing report is visibly unknown, never healthy.

## Authorization and UX

Inventory is readable by `agent:view_privileged`, matching the existing
privileged managed-agent runtime facts. The machine credential may only report
for itself. The AI agents page shows server health and inventory; it has no
allow/deny controls. Members receive no privileged inventory facts.

## Acceptance

- One legacy and one current snapshot normalize to the same server/tool/
  resource/prompt model.
- Pagination, list-change capability, modern metadata, schema hashing and
  bounded rejection are covered.
- Cross-org, human, and wrong-agent writes fail closed.
- No report can persist secrets or resource/prompt/tool-result content.
- UI distinguishes checking, healthy, stale/failed, new, changed and absent;
  it never presents observation as enforcement.
