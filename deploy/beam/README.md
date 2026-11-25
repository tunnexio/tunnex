# Local Sharing (Beam) operator runbook

Local Sharing is opt-in. The base stack does not start its proxy, and
organization policy defaults off. Releases publish a signed
`tunnex-beam-proxy` image, and `upgrade.sh` manages this overlay as
`<install>/local-sharing.yml` (LS-UX-1 D.1/D.2). **Use "Install (managed
layout)" below.** The sections before it explain the topology and checks.
Serving on a host's single public 443 next to Caddy or App Access is planned
(LS-EDGE-1). Until then the browser listener needs its own public IPv4
address.

## Supported process topology

One proxy process serves two independent TLS listeners: browser HTTPS and desktop
mTLS CONNECT. Both can use external port 443 on distinct explicitly chosen host
IP addresses, or the connector can use another port (`TUNNEX_BEAM_CONNECTOR_PORT`)
on any address. The browser wildcard DNS points to the browser address; the fixed
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

## Alongside App Access, and the domain rule (LS-UX-1)

Local Sharing does not need App Access, and App Access does not need Local
Sharing. When both run on one host:

- Local Sharing has its own proxy (`beam-proxy`). `app-proxy` cannot serve
  shares. The two overlays share only the API's private authority listener
  `:8445` and the `app_restore` barrier volume, and both overlays set them the
  same way.
- The **browser listener must be on TCP 443** (the readiness check probes the
  wildcard on 443). If `app-proxy` already owns 443 on the host address, give
  Local Sharing a second public IPv4 address (`TUNNEX_BEAM_PUBLIC_BIND_IP`).
- The **connector can share an address** if it uses another port. Set
  `TUNNEX_BEAM_CONNECTOR_PORT` (e.g. `8447`; not `8444`, which App Access
  gateways use, and not 8445 or 9093). Then use for example
  `https://<console host>:8447` as the connector URL. The connector always
  verifies the TLS name `tunnex-beam-proxy`, not the DNS name.
- The **sharing domain** must be the console host itself or a different
  registrable domain (siblings such as `share.<console domain>` are refused).
  It must also not equal or nest inside the App Access base domain. In
  practice, when App Access uses the console host, Local Sharing needs its own
  registrable domain and its own `*.<sharing domain>` certificate.

## Provision privately

Use the current control-plane `backupctl` with its existing database, sealed CA and
restore-barrier configuration:

```sh
backupctl app-proxy-issue --purpose local-sharing --name beam-proxy --output /private/beam/authority.token
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
`TUNNEX_BEAM_PROXY_SECRETS_DIR`, `TUNNEX_BEAM_PUBLIC_BIND_IP`,
`TUNNEX_BEAM_CONNECTOR_BIND_IP` and optionally `TUNNEX_BEAM_CONNECTOR_PORT`
(default 443) in a private environment file. Do not put real
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

## Enable in one step (LS-UX-1 E.2)

You need a sharing domain of its own, a trusted wildcard certificate for it,
and DNS `*.<sharing domain>` pointing to this server's public address. Then,
in the installation directory:

```sh
./tunnex-local-sharing enable --domain share-example.dev --cert fullchain.pem --key privkey.pem
./tunnex-local-sharing enable --domain share-example.dev --cert fullchain.pem --key privkey.pem --apply
```

The first command only shows the plan. The second one:
- pins the signed proxy from the installed release;
- installs `local-sharing.yml`;
- issues the purpose-bound credential and the connector certificate;
- installs your certificate;
- moves the console and App Access behind the single-IP edge on the same
  public 443;
- starts everything.

It then prints what is left: the publishers' firewall port (default 8447) and
the console check. `./tunnex-local-sharing status` shows the state.
`./tunnex-local-sharing disable --apply` gives 443 back and turns Local
Sharing off. Use `--layout dedicated --public-ip ADDRESS` to give shares their
own address instead. The command is installed by every upgrade. On an older
host, copy it once with `docker compose cp
api:/usr/share/tunnex/host/beam/tunnex-local-sharing.py ./tunnex-local-sharing`.

**How the single IP works.** `beam-proxy` owns public 443 and reads only the
TLS server name. Share hostnames are decrypted by `beam-proxy` itself.
Everything else (console, App Access, ACME) is passed through undecrypted to
Caddy or `app-proxy`, with a PROXY v2 header carrying the real client address:
- Caddy trusts that header only from the edge's fixed address on the internal
  `edge` network.
- `app-proxy` trusts it only with the private edge token.

**IPv6:** edge mode publishes 443 on IPv4 only. If this host serves the
console to IPv6 clients, use `--layout dedicated` or add an IPv6 port mapping
for `beam-proxy` yourself. The latter is not managed by the upgrade.

If the default subnet `172.31.254.0/29` collides with a local network, set
`TUNNEX_EDGE_SUBNET`, `TUNNEX_EDGE_PROXY_ADDRESS` and
`TUNNEX_EDGE_CADDY_ADDRESS` in `.env` before enabling.

## Manual install (reference)

The command above performs these steps.


Run in the installation directory (for example `/opt/tunnex`). `F` is your
current file list: `-f tunnex.yml`, plus `-f app-access.yml` when App Access is
installed. The release must include the signed Local Sharing proxy.

```sh
F="-f tunnex.yml"            # or: F="-f tunnex.yml -f app-access.yml"
# 1. The managed overlay, from the signed API image you are running.
docker compose $F cp api:/usr/share/tunnex/host/beam/compose.yml local-sharing.yml
echo "TUNNEX_LOCAL_SHARING_COMPOSE_SHA256=$(sha256sum local-sharing.yml | cut -d' ' -f1)" >> .env
# 2. The signed proxy image, by digest.
docker compose $F exec -T api sh -c 'releaseverify -manifest /var/lib/tunnex/release.json \
  -public-key "$TUNNEX_RELEASE_PUBLIC_KEY" -require-beam-proxy -print-env' \
  | grep '^TUNNEX_BEAM_PROXY_IMAGE=' >> .env
# 3. Proxy credential and connector certificate (writable restore lock, new private dir).
install -d -o 10001 -g 10001 -m 0700 /opt/tunnex/beam-secrets
cat > /tmp/ls-issue.yml <<'YAML'
services:
  api:
    volumes:
      - {type: volume, source: app_restore, target: /var/lib/tunnex/app-restore, read_only: false}
      - {type: bind, source: /opt/tunnex/beam-secrets, target: /out}
YAML
docker compose $F -f local-sharing.yml -f /tmp/ls-issue.yml run --rm --no-deps -T \
  --entrypoint backupctl api app-proxy-issue --purpose local-sharing --name local-sharing-proxy --output /out/authority.token
docker compose $F -f local-sharing.yml -f /tmp/ls-issue.yml run --rm --no-deps -T \
  --entrypoint backupctl api beam-proxy-certificate --output-dir /out/connector
mv /opt/tunnex/beam-secrets/connector/* /opt/tunnex/beam-secrets/ && rmdir /opt/tunnex/beam-secrets/connector
# 4. Your wildcard certificate for *.<sharing domain> (full chain + key).
install -o 10001 -g 10001 -m 0400 fullchain.pem /opt/tunnex/beam-secrets/public-cert.pem
install -o 10001 -g 10001 -m 0400 privkey.pem   /opt/tunnex/beam-secrets/public-key.pem
# 5. Settings (the domain and URL only pre-fill the console form).
cat >> .env <<'ENV'
TUNNEX_BEAM_BASE_DOMAIN=share-example.dev
TUNNEX_BEAM_PROXY_URL=https://cp.example.com:8447
TUNNEX_BEAM_PROXY_SECRETS_DIR=/opt/tunnex/beam-secrets
TUNNEX_BEAM_PUBLIC_BIND_IP=203.0.113.20
TUNNEX_BEAM_CONNECTOR_BIND_IP=203.0.113.10
TUNNEX_BEAM_CONNECTOR_PORT=8447
ENV
sed -i 's/^COMPOSE_PROFILES=\(.*\)$/COMPOSE_PROFILES=\1,beam/' .env
# 6. Start (local-sharing.yml is always the last file). Name the services:
#    a bare `up -d` would also start every stopped service without a profile,
#    such as node-agent on a control plane whose gateway runs elsewhere.
#    Add app-proxy when App Access is installed.
docker compose $F -f local-sharing.yml up -d api caddy beam-proxy
```

Then, in the console, **Settings → Local Sharing domain**: enter the domain and
connector URL, allow Local Sharing, save, and select **Check DNS and TLS**.

## Upgrading

The ordinary one-command upgrade (`upgrade.sh --apply` or the dashboard)
manages this profile, the same way it manages App Access:
- it verifies and pins the signed `TUNNEX_BEAM_PROXY_IMAGE`;
- it replaces `local-sharing.yml` with the new release's copy;
- it stops `beam-proxy` before the API migrates, then starts it again once the
  API is healthy.

Live shares end at the restart. Publishers run their command again. Policy,
settings, history and the restore volume are kept. Drift is refused before any
change, and the refusal names the setting: a changed overlay, a secrets
directory or port binding that differs from `.env`, a missing setting, or a
release without the signed proxy. If the new proxy does not become healthy,
it is left stopped while the upgraded control plane keeps running. Fix the
cause and run the upgrade again.

**Returning to the previous release (rollback).** The product's rule is
forward fix: re-run the upgrade. If you must restore the verified pre-upgrade
backup instead:
- **App Access installed:** use the App Access restore runner
  (`app-access-restore.py`, see the App Access README). Keep `beam-proxy`
  stopped until it finishes.
- **Local Sharing only:** there is no automated fenced restore runner yet.
  1. Stop `beam-proxy`.
  2. Restore the database with the base procedure (`docs/backup-restore.md`).
  3. Revoke the old proxy credential with `backupctl app-proxy-revoke`.
  4. Issue a new one (step 3 above).
  5. Start the proxy, then run **Check DNS and TLS** again.

  Shares that were live at backup time cannot resume, so publishers create
  new ones. This path is documented, not qualified.

## Adopting a hand-written setup

If `beam-proxy` was started from another overlay file, the upgrade refuses and
prints these steps. Copy the managed overlay (step 1 above), keep your
`TUNNEX_BEAM_*` values in `.env`, then recreate:
`docker compose $F -f local-sharing.yml up -d api caddy beam-proxy` (add
`app-proxy` when App Access is installed). Remove the old overlay from
your command line. The next upgrade then manages it.

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
