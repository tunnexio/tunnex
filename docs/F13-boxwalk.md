# F13 — MCP OAuth protected-resource trust box-walk

Status: **SATISFIES the live consent and sealed-custody path.**

The AWS DEV control plane ran local F13 source build `896ef15` (not a published
release). The walk used a disposable, TLS-fronted OAuth-protected MCP provider
on the control-plane Docker network and the managed agent `f11-alert-live`.

## Acceptance evidence

- [x] Pre-walk CP configuration and PostgreSQL backups were made under the
      Ubuntu operator home. API/Web were rebuilt from F13 source; migration
      `0102_agent_mcp_oauth` applied cleanly.
- [x] The agent reported a protected MCP resource, bound to
      `https://internal.tunnex.app/f13-mcp`, its HTTPS authorization-server
      issuer, and the `mcp.read` scope. The runtime sent no authorization
      header during discovery.
- [x] The owner started authorization-code consent with PKCE from the Agents
      surface and approved it at the temporary provider. The callback returned
      to the CP and the UI reported `connected` with an expiry.
- [x] Database proof recorded booleans only: client secret, access token, and
      refresh token were sealed; a secret fingerprint and expiry were present;
      the state was `connected`; no failure code was set. No secret value was
      returned by the readable API or rendered in the UI.
- [x] The provider had no MCP tool/content endpoint and emitted no tool call.
- [x] A walk finding (`896ef15`) prevents a second consent start against an
      already-connected endpoint; UI hides the form and the API returns a
      conflict.

## Cleanup

- [x] Deleted only the disposable F13 OAuth connection. The last inventory
      snapshot remains as historical observation; without its provider it
      cannot start a new valid consent flow.
- [x] Removed the disposable provider and its temporary Nginx routes.
- [x] Restored the managed agent's original binary and removed the temporary
      `TUNNEX_MCP_INVENTORY_ENDPOINTS` systemd override.
- [x] CP API/Web remain on the local F13 walk build for review; no release tag,
      image publication, push, PR, or merge was performed by this walk.

## Scope boundary

F13 proves discovery, consent, and custody only. It deliberately does not
hand credentials to the agent or authorize MCP tool use; F14 owns that policy
and runtime handoff.
