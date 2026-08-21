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

## Live wire proof — pending a CP walk

This is not satisfied by local tests. On a disposable managed agent host:

1. Configure one inventory endpoint and the explicit loopback proxy:

   ```sh
   TUNNEX_MCP_INVENTORY_ENDPOINTS=https://mcp.example/rpc
   TUNNEX_MCP_PROXY_LISTEN=127.0.0.1:17100
   TUNNEX_MCP_PROXY_UPSTREAM=https://mcp.example/rpc
   ```

2. Let inventory report, then choose exactly one tool in **AI agents → MCP tool
   policy** and save it.
3. Point an MCP HTTP client deliberately at `http://127.0.0.1:17100`; call the
   selected tool and prove the upstream receives it.
4. Send a request whose body names a different tool while its mirrored header
   names the allowed tool; prove the proxy rejects it and the upstream receives
   nothing.
5. Stop inventory reporting for more than one minute; prove the proxy denies
   the formerly allowed call. Resume reporting and prove the same unchanged
   tool becomes eligible again.
6. For an F13-connected protected resource, prove the upstream sees only the
   runtime leased bearer (never the MCP client's bearer), then inspect the API,
   runtime report, UI, and logs to confirm no token appears.

Direct calls to `https://mcp.example/rpc` are intentionally outside F14 and
must be documented as such. The CP walk is the trigger to mark F14 complete.
