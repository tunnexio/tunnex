# F12 — MCP server and tool inventory box-walk

Status: **SATISFIES the shadow-observation wire path.**

The AWS DEV walk deployed the F12 API and web build from source commit
`03bcfe5`, then used the corrected Linux managed-runtime artifact from
`1130ad9`. No release was published and no production image tag was changed.
The temporary MCP source listened only on the managed-agent host's loopback
interface; it exposed one listable tool, resource, and prompt. It received no
tool call or resource read.

## Acceptance

- [x] The control plane was backed up before the walk: deployment files, current
      API/web image rollback tags, and a PostgreSQL dump.
- [x] Only `api` and `web` were recreated. PostgreSQL, Redis, nginx, Caddy, and
      the node agent remained healthy.
- [x] Migration 0101 created `agent_mcp_inventory` and the API health endpoint
      remained healthy.
- [x] A live managed runtime negotiated MCP `2025-11-25`, then listed exactly
      one tool, one resource, and one prompt without invoking a tool or reading
      resource content.
- [x] The persisted snapshot reported server `f12-walk-mcp`, status `healthy`,
      and item counts `1/1/1`.
- [x] The released Agents UI rendered the MCP inventory panel in shadow mode;
      it contains no enforcement control.
- [x] The temporary runtime binary, systemd environment override, and loopback
      MCP process were removed. The managed-agent host is again running its
      original runtime binary and active service.

## Regression discovered and fixed

The first wire walk exposed that standard MCP camel-case fields
`inputSchema`, `outputSchema`, and `mimeType` were decoded as their persisted
snake-case names, causing a valid inventory to appear as `invalid_inventory`.
Commit `1130ad9` maps those wire fields explicitly. Its focused normalization
test passes, and the repeated live report persisted `healthy`.
