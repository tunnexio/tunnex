# Local authenticated MCP wire fixture

This fixture runs as a separate HTTPS server process on `127.0.0.1:54931`.
The Go harness uses the product collector and MCP proxy, exposed only on
`127.0.0.1:54932`. It accepts a synthetic credential from a private file and reads
an explicit allowlist from another file. No upstream tool contacts external data.

`result.json` is sanitized evidence from the 2026-09-09 walk. The private key,
synthetic token, CA, and temporary policy remain outside Git in
`/private/tmp/tunnex-mcp-auth0909` (directory mode 0700; private files 0600).

## Scope

- Authenticated initialize / initialized / two-page tools/list.
- Three discovered tool names, descriptions and normalized schemas.
- HTTP 401 without credentials and HTTP 403 on denied or failed later pages.
- Failed later-page discovery publishes no partial healthy catalog.
- Selected tool succeeds via the production proxy despite a forged caller token.
- Unselected and revoked tools return 403 without reaching the MCP server.

The harness supplies an endpoint-bound credential source and policy file. It
does **not** prove API credential leasing, managed-agent enrollment, database
reconciliation, OAuth consent, network tunneling, or the browser connect/grant
flow. Those remain pending in `docs/S-MCP-authenticated-discovery-review.md`.

## Repeat

Use a new fixture process for each run so the upstream call counter starts at
zero. Generate a short-lived local certificate with SAN IP `127.0.0.1`, save its
key/PEM and a random synthetic token in a private temporary directory, and create
`policy.json` containing `["read_issue"]`. Do not use a provider credential.

From the repository root, start the fixture with that directory's paths:

```sh
python3 walk-artifacts/mcp-auth0909/fixture.py \
  --cert /private/tmp/tunnex-mcp-auth0909/cert.pem \
  --key /private/tmp/tunnex-mcp-auth0909/key.pem \
  --token-file /private/tmp/tunnex-mcp-auth0909/token
```

In another terminal, from `apps/cli`:

```sh
GOFLAGS=-mod=readonly go run ./walk/mcp-auth0909/main.go \
  --ca /private/tmp/tunnex-mcp-auth0909/cert.pem \
  --token-file /private/tmp/tunnex-mcp-auth0909/token \
  --policy-file /private/tmp/tunnex-mcp-auth0909/policy.json \
  --output /private/tmp/tunnex-mcp-auth0909/discovery.json
```

Then run the assertions from the repository root:

```sh
python3 walk-artifacts/mcp-auth0909/verify.py \
  --state-dir /private/tmp/tunnex-mcp-auth0909
```

The verifier revokes the fixture allowlist during the run. It emits and saves
only status codes, tool names and the acceptance boundary. Stop both local
processes with Ctrl-C afterward; no Docker VM or Mac restart is needed.
