# Beam operator runbook

Beam is opt-in. `docker-compose.yml` does not start its proxy, and organization
policy defaults off. This override is a local implementation artifact; published
signed proxy images, Windows execution, production certificate topology and a
complete installer walkthrough remain qualification gates.

## Supported process topology

One proxy process serves two independent TLS listeners: browser HTTPS and desktop
mTLS CONNECT. Both can use external port 443 on distinct explicitly chosen host
IP addresses. The browser wildcard DNS points to the browser address; the fixed
connector URL points to the connector address. Using the same IP for both port
443 mappings fails to bind. A shared-IP TLS passthrough edge is outside the current
qualified override. No gateway or VPN connection carries the desktop connector.

Choose a Beam registrable domain separate from the console domain. Use wildcard
DNS and a public certificate for `*.BEAM_BASE_DOMAIN`. The connector listener uses
the control-plane-signed certificate with TLS identity `tunnex-beam-proxy`; the
desktop verifies the returned control-plane CA and that exact identity. Do not
replace it with a public wildcard certificate or disable certificate verification.
The console URL must be HTTPS. Installation serving defaults off. Environment
domain/connector values are suggestions for the operator form; they cannot grant
admission. `TUNNEX_BEAM_DOMAIN_READY` does not substitute for measured readiness.

## Provision privately

Use the current control-plane `backupctl` with its existing database, sealed CA and
restore-barrier configuration:

```sh
backupctl app-proxy-issue --name beam-proxy --output /private/beam/authority.token
backupctl beam-proxy-certificate --output-dir /private/beam/connector
```

The credential output and certificate directory must be new, absolute private
paths. Assemble `authority.token`, `agent-ca.pem`, `gateway-cert.pem`,
`gateway-key.pem`, `public-cert.pem` and `public-key.pem` in the dedicated secrets
directory. Give runtime UID 10001 access, keep credential and keys mode 0400/0600,
and mount the directory read-only. Never copy bootstrap credentials into desktop
configuration, the renderer bundle or a Git commit.

The independent `app_restore` volume is shared read-only by serving processes and
retained separately from database data. The explicit initialization service sets
its owner and private directory mode. Supported restore must hold this barrier and
revoke old Beam authority before resuming serving. Restoring a raw database without
the supported fencing procedure is not a qualified recovery path.

## Configure and inspect before enabling

Set `APP_BASE_URL`, `TUNNEX_BEAM_BASE_DOMAIN`, `TUNNEX_BEAM_PROXY_URL`,
`TUNNEX_BEAM_PROXY_IMAGE` (verified immutable digest),
`TUNNEX_BEAM_PROXY_SECRETS_DIR`, `TUNNEX_BEAM_PUBLIC_BIND_IP` and
`TUNNEX_BEAM_CONNECTOR_BIND_IP` in a private environment file. Do not put real
credentials into shell history or documentation. The service credential belongs in
its private mounted file, not environment variables.

```sh
docker compose --env-file /private/beam.env \
  -f docker-compose.yml -f deploy/beam/compose.yml --profile beam config --quiet

docker compose --env-file /private/beam.env \
  -f docker-compose.yml -f deploy/beam/compose.yml --profile beam config --format json \
  | python3 deploy/beam/verify-config.py
```

This renders configuration only. Starting/upgrading a deployed stack is a separate
operator action. Local development uses `tests/beam-local/compose.yaml`, distinct
project names, private fixtures and Docker-managed artifact volumes.

In the console's installation Beam settings, save the domain and connector URL
with the current configuration version, enable serving, and run the DNS/TLS check.
An elected control-plane worker refreshes the bounded readiness measurement.
All replicas require a current database proof for the exact saved configuration,
trust roots, console URL and restore barrier. Changing serving targets or disabling
serving revokes affected nonterminal shares atomically; the form requires confirming
this impact. A failed or expired measurement denies admission and lease renewal.
Then enable each organization's Beam policy. Delegate explicit publisher groups and reviewer
users/groups, lifetime and quota. A random hostname is a locator; access still
requires a permitted current browser identity and grant.

## Health, disable and rotation

Operator endpoints are bound to proxy loopback: `/livez`, `/readyz`, `/metrics` on
9093. They must not be published through the browser edge. Metrics use
`tunnex_beam_proxy_*`, contain no URLs, org/share IDs, cookies or credentials, and
include bounded reservations and authority failures. Readiness checks current
control-plane domain authority; it is not proof of public DNS or browser trust.

Disable the affected organization policy to revoke its shares. Withdraw installation
serving in installation settings to revoke shares and deny admission and lease
renewal across organizations. Streams stop
within the five-second acceptance ceiling. Restoring readiness does not resurrect
terminal shares. Graceful proxy shutdown drains/terminates connections; existing
streams do not migrate across a restart.

For certificate rotation, privately stage new verified material, drain/restart the
one proxy, and have eligible publishers explicitly reconnect. Verify the exact CA,
identity and expiry before enabling. A new proxy certificate is not a new publisher
identity. Never extend a share's expiry because a process restarted. Credential
withdrawal uses the existing `backupctl app-proxy-revoke` command and current
authority; verify admission fails before removing old material.

For rollback, first disable Beam and drain the proxy. Preserve database backup,
roots and restore-barrier state. Database downgrade/upgrading again must pass in an
isolated database before an older binary is permitted to run. Removing this override
stops wiring Beam into a subsequently recreated base stack; it does not itself stop
an existing proxy container or delete retained state. Full deployed rollback remains
a qualification gate.
