# App Access operator composition

These files prepare an explicit opt-in deployment. The base Compose stack and Helm
charts keep App Access disabled. Installer reinstall refuses an existing scoped App Access composition, including stopped participants, before replacing deployment files.

## Upgrading an installation with App Access

Use the ordinary single upgrade command (`upgrade.sh --apply`, or the dashboard
upgrade), including for releases that add migrations. See
[UPG-1](../../docs/UPG-1-one-click-upgrade-with-app-access.md). The upgrade
manages this overlay as `<install>/app-access.yml`, taken from the target
release's signed API image (UPG-2) and hashed. It pins the signed `TUNNEX_APP_PROXY_IMAGE`
(`-require-app-proxy`) and keeps the `app-access` profile.

Before backing up, the upgrade runs `backupctl app-preflight`, which records the
installation authority. The upgrade then stops the proxy and lets the API
migrate. After migration it checks, with the new binary, that the authority is
unchanged and the schema is clean. Only then does it start the proxy. A pending
restore marker, a dirty schema, incomplete authority, a target release without a
signed proxy, or any identity drift refuses the upgrade before mutation. Identity
drift means any of: the restore volume is not `<project>_app_restore`, the proxy
secrets directory or port differs from `.env`, more than one API or proxy exists,
or the composition is unknown. Keep `TUNNEX_APP_ACCESS_BASE_DOMAIN`,
`TUNNEX_APP_PROXY_SECRETS_DIR` and, when they are not the defaults,
`TUNNEX_APP_PROXY_BIND_IP` and `TUNNEX_APP_PROXY_PUBLIC_PORT` in the installation
`.env`. A hand-composed overlay is adopted once these checks pass. It is left on
disk but no longer used.

On a failure after migration the proxy stays stopped. To roll back, restore the
named pre-upgrade backup with the installed `app-access-restore.py` (this file's
`restore.py`). Recovery invalidates authority as described below. Never use raw
`pg_restore` or a down migration.

Installations whose installed `upgrade.sh` predates the one-click upgrade refuse
before they can update themselves. Replace the helper once with the verified
target release's copy, using the one-time step in
[docs/upgrade.md](../../docs/upgrade.md#release-notes-one-time-step-for-hosts-on-v0145-or-older).
From then on every upgrade runs the target release's own helper, so this is never
needed again. The same-schema `upgrade.py` below remains
a manual image-replacement tool. Enabling infrastructure does not grant entitlement,
opt in an organization, publish an application, or create a browser session.

Before installing or upgrading, verify the signed release descriptor with the trusted
`releaseverify -require-app-proxy -print-env -platform amd64` (or arm64). Use its
`TUNNEX_APP_PROXY_IMAGE` immutable digest; do not substitute a mutable tag. Older
signed releases remain usable without App Access, but cannot satisfy this opt-in
preflight. The existing protected CI release job now builds and signs the additional
image; no image has been published by this local work.

## Gateways learn the proxy endpoint from the control plane (AA-EN-1)

The managed overlay publishes the proxy's gateway listener on
`${TUNNEX_APP_PROXY_GATEWAY_BIND_IP:-0.0.0.0}:${TUNNEX_APP_PROXY_GATEWAY_PORT:-8444}`.
It requires a client certificate from the enrollment CA, like the agent channel
on 8443. Set `TUNNEX_APP_PROXY_GATEWAY_BIND_IP` in `.env` to narrow it, for example
to a private address. Allow TCP to that port from your gateways in the cloud
firewall; the product cannot change firewall rules.

The control plane tells each gateway where the listener is over the existing
mTLS agent channel (`GET /agent/app-access/proxy-endpoint`). By default the gateway
dials the same host it uses for its agent channel, at that port. If gateways must
use another address (split networks), set `TUNNEX_APP_PROXY_GATEWAY_HOST` in `.env`
to a bare hostname or IP. The gateway always pins the TLS server name
`tunnex-app-proxy` and trusts only the enrollment CA, so it dials an IP address
directly: no `--add-host` or `/etc/hosts` entry is needed. Delivery is on only when
App Access is composed, `TUNNEX_APP_ACCESS_LOCKED` is not `true`, App Access is
entitled, and the gateway's organization has the feature on. A listener bound only to
loopback (`TUNNEX_APP_PROXY_GATEWAY_BIND_IP` in 127.0.0.0/8 or `::1`) is not
delivered, because no remote gateway can reach it, unless
`TUNNEX_APP_PROXY_GATEWAY_HOST` names an address explicitly (for example a tunnel).

On a gateway, `TUNNEX_APP_PROXY_URL` is read as:

- unset or empty: follow the control plane; the browser connector starts, moves or
  stops within about 5 seconds, without a restart;
- a URL (for example `https://tunnex-app-proxy:8444`): a local override that always
  wins, as before;
- `off`: never run the browser connector on this gateway.

Upgrade the control plane before gateways. An older control plane answers 404, and
a following gateway then keeps its current state.

## Adopting a hand-written composition: `tunnex-app-access adopt`

Upgrades admit exactly `tunnex.yml` plus the managed `app-access.yml`. A host that
was composed by hand with more files (for example the demo's `tunnex.yml` +
`app-access.yml` + `app-access-demo.yml`, where the proxy owns public 443 and
forwards the console to Caddy, and the gateway listener is published on a private
address) is refused until it is adopted.

1. Take the command from the verified target release. Verify the release
   descriptor as for the one-time step in [docs/upgrade.md](../../docs/upgrade.md),
   then copy the host files out of its API image without running it:

   ```sh
   cid=$(docker create --pull never --network none ghcr.io/tunnexio/tunnex-api@sha256:<verified digest>)
   mkdir -m 0700 /root/tunnex-host && docker cp "$cid:/usr/share/tunnex/host/." /root/tunnex-host
   docker rm "$cid"
   ```

2. Review the plan (dry run, nothing changes):

   ```sh
   sudo python3 /root/tunnex-host/app-access/tunnex-app-access.py --directory /home/ubuntu/tunnex adopt
   ```

   It inspects container labels, mounts and port bindings only (never container
   environment). It refuses identity drift: more than one API or proxy, a restore
   volume other than `<project>_app_restore`, a secrets directory other than
   `TUNNEX_APP_PROXY_SECRETS_DIR`, an unsigned proxy pin, unexpected or implicit
   port bindings. It renders the composition with and without the hand-written
   overlays and refuses anything they change beyond Caddy giving up 443, the proxy
   ports and the console upstream settings. Move other settings into `.env` or
   remove them first.

3. Apply with `--apply`. It keeps a private backup
   (`<install>/app-access-adopt-<time>/`, with `ROLLBACK.txt`), installs the managed
   overlay, and writes to `.env`: the proxy and gateway bind addresses and ports as
   they run today, the console forwarding (`TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL`
   and `..._SERVER_NAME`), `TUNNEX_EDGE_HTTPS_PUBLISH=127.0.0.1:8446` when the proxy
   owns 443 (Caddy then publishes HTTPS on loopback only), the gateway host override
   when the listener is on a specific address, the overlay hash, and a record of the
   adopted composition with the hash of each hand-written overlay. The secrets
   directory, the restore volume, the proxy credential and the certificates are not
   touched. No container is stopped or recreated, so the console stays as it is.
   Running it again changes nothing.

4. Run the upgrade (`upgrade.sh`, then `upgrade.sh --apply`, or the dashboard). Its
   admission accepts the recorded composition only while the hand-written overlays
   are unchanged, recreates the stack from the managed files, and removes the
   record once healthy. The hand-written overlays stay on disk, unused. If that
   upgrade fails after the API was recreated, running it again is admitted: the
   stopped proxy still carries the recorded composition, which is accepted only
   while it matches the record.

Rollback: before the upgrade, copy the backed-up `.env` and `app-access.yml` back
(`ROLLBACK.txt` has the exact commands); nothing running had changed. After the
upgrade, use the upgrade's own rollback (`app-access-restore.py` with the
pre-upgrade backup); the hand-written layout is not restored.

Adopted installations keep terminate-and-forward on 443 (the proxy terminates the
console's TLS with its public certificate, which must cover the portal hostname).
New installations will use SNI passthrough instead (AA-EN-1 E2, Phase 2).

### Console reachability during an upgrade (adopted installations)

This is accepted behaviour (AA-EN-1 founder ruling 1); SNI passthrough in Phase 2
removes it for new installations. On an adopted host the console reaches users
through the App Access proxy on public 443. The upgrade stops the proxy while the
API migrates and starts it only after the authority check passes, and it leaves the
proxy stopped if the upgrade fails. So:

- during an upgrade the console is unreachable on public 443 for its duration;
- after a failed upgrade it stays unreachable, and the dashboard cannot show the
  failure or offer "Run the upgrade again".

Recover from the command line on the host:

1. Read the result: `cat <install>/upgrade-state/status/status` (or the output of
   the command you ran). Note `reason_code` and the backup file names.
2. If `reason_code` is `app_access_authority_changed`, or the output says
   "Do not re-run this upgrade", stop: follow the restore runbook it prints
   (`app-access-restore.py` with the named pre-upgrade backup).
3. Otherwise fix the reported cause and run the same release again (the supported
   forward fix; a same-sequence, same-source re-run is accepted, never an older
   release):

   ```sh
   cd <install>
   sudo ./upgrade.sh             # dry run: verifies and shows the plan
   sudo ./upgrade.sh --apply
   ```

4. When it reports healthy, the proxy is started again and the console is back on
   public 443.

## Renewing the public certificate: `tunnex-app-access renew`

Until automatic renewal ships (AA-EN-1 Phase 1b), renew the public wildcard with
certbot's DNS-01 challenge and install it with the host command, which the upgrade
installs as `<install>/tunnex-app-access`:

```sh
# Operator step: renew with a DNS API token scoped to the zone (Cloudflare shown).
sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
  -d '*.cp.example.com' -d cp.example.com
# Review, then install with a controlled proxy restart.
sudo /home/ubuntu/tunnex/tunnex-app-access --directory /home/ubuntu/tunnex renew \
  --cert /etc/letsencrypt/live/cp.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/cp.example.com/privkey.pem
sudo /home/ubuntu/tunnex/tunnex-app-access --directory /home/ubuntu/tunnex renew --apply \
  --cert /etc/letsencrypt/live/cp.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/cp.example.com/privkey.pem
```

Include the portal name (`-d cp.example.com`) when the proxy forwards the console.
`renew` checks, with the system trust store (or `--ca-file` for a private CA): the
full chain, that a random name under `*.<base domain>` and (with console forwarding)
the portal hostname are covered, the validity window, that the key matches, at least
7 days left, and a later expiry than the installed certificate
(`--allow-earlier-expiry` overrides the last check). With `--apply` it writes
`public-cert.pem` and `public-key.pem` atomically as mode 0400 files owned like the
existing ones (uid 10001), keeps the previous pair as `*.previous`, restarts only
the proxy and waits for it to be ready. If the proxy does not become ready it puts
the previous pair back and restarts it again. The restart closes open streams;
clients reconnect. Nothing secret is printed. A root cron job or systemd timer can
run the two commands; certbot's `--deploy-hook` is a good place for the second.

The gateway listener certificate (`gateway-cert.pem`, valid 365 days) is not renewed
by this command yet; follow [CERTIFICATES.md](CERTIFICATES.md).

## Reviewed install, same-schema replacement and rollback

For an initial opt-in install, cache the API and proxy images selected by the
verified release descriptor before using Compose. Preserve an encrypted backup,
the separately retained master key and the external restore volume. Start the
explicit reviewed composition normally; inspect API health, strict public TLS,
private authority connectivity and the dedicated proxy identity. Infrastructure
startup does not publish an app. Do not replace an existing deployment with an
older API binary or run a down migration.

For an already installed single-host API/proxy pair, `upgrade.py` admits only
cached immutable images from the explicitly supplied trusted release verifier and
public key. Both current and target API images must contain `backupctl
app-preflight`, report the same clean schema equal to their embedded migration
ceiling, and report the same completed installation generation/version. A pending
external barrier, missing authority, older/future schema, executable mount override,
foreign checkout or changed participant refuses replacement. The preflight does
not initialize secrets, migrate the database or recover authority.

Review a plan without stopping listeners:

```sh
python3 deploy/app-access/upgrade.py --docker-socket /run/docker.sock \
  --project PROJECT --directory CHECKOUT \
  --compose-file CHECKOUT/docker-compose.yml \
  --compose-file CHECKOUT/deploy/app-access/compose.yml \
  --manifest VERIFIED.release.json --releaseverify TRUSTED_RELEASEVERIFY \
  --public-key PINNED_ED25519_PUBLIC_KEY --platform arm64
```

Apply by repeating the same arguments with `--apply-plan-sha256 PLAN_SHA256` from
that output. The hash binds the signed descriptor bytes, effective reviewed
configuration, cached image identities, exact containers and authority snapshot.
A changed plan stops nothing. Only API/proxy images change; environment values,
mounts (including secret and marker sources/permissions), ports and network settings
come from the frozen reviewed configuration. This checks explicitly configured
values and Docker mount identities. Network objects remain pinned by canonical
Docker IDs; stopped replacements may reserve reviewed network names without an
attached endpoint, and are never secretly started to populate `NetworkID`. It
does not promise every base-image default
ENV is identical across releases. The helper never builds, pulls, replaces operator
files, runs schema down/up, provisions credentials or publishes apps.

After replacement both listeners remain stopped. Persist the verified API/proxy
pins in your private operator configuration, inspect the stopped participants and
then intentionally start only those services with the same composition. Verify API
health, strict proxy TLS and current authority before reopening traffic. Failures
or an unknown apply outcome require inspecting the actual stopped participants;
do not blindly retry a start. The supported external restore barrier continues to
block either binary if recovery starts during this procedure.

Rollback uses the same plan/apply process with the prior verified descriptor and
cached images. It is accepted only if that API's embedded schema ceiling still
matches the current clean schema. There is no schema173-to172 downgrade; a
schema-changing upgrade requires a separately qualified offline procedure. A
binary predating `app-preflight` cannot use this path.

Local qualification exercised distinct cached API/proxy image identities,
installation/restart, same-schema replacement and rollback with unchanged
schema173/generation/version and retained volumes. Each explicit restart returned
API health200 and strict TLS1.3 proxy403 for the intentionally invalid child
credential. The local adapter used an ephemeral test signer and local image IDs;
it did not claim registry digest distribution, a production release signature,
positive publication or prior-schema compatibility. Shipping admission still
requires the exact signed registry RepoDigest. Kubernetes upgrades remain outside
this single-host procedure.

Provision a dedicated credential offline using `backupctl app-proxy-issue --name
NAME --output ABSOLUTE_PATH`. Its output directory is private0700 and token file0600;
there is no token stdout. Configure the absolute shared `TUNNEX_APP_ACCESS_RESTORE_MARKER` and give the offline helper write access to that exact private volume. Issuance/revocation hold the same stable restore lock until the DB decision and private-file persistence finish; a pending restore refuses them. Use `app-proxy-revoke --id UUID --expected-version N` to
revoke that identity. Do not use human tokens, gateway credentials, or console cookies.

For Compose, explicitly combine the root compose file with this `compose.yml` and
select profile `app-access` after review. Supply the registered app base
and HTTPS console origin, signed image digest, and a uid10001-readable private secret
directory containing proxy-credential, public-cert.pem/public-key.pem,
gateway-cert.pem/gateway-key.pem, and agent-ca.pem. The public certificate covers
registered app hosts. The gateway certificate uses the enrollment CA and exact SAN
`tunnex-app-proxy`; the authority endpoint separately uses `tunnex-app-authority`.
The console may use an independent known ICANN registrable domain, or be exactly
the app base hostname: for example, portal `internal.tunnex.app` and application
`demo.internal.tunnex.app`. Other same-site arrangements are refused. An explicitly
configured HTTPS IP portal is supported; applications still need separate DNS
hostnames, not paths on the portal/IP origin. Private PSL hosting and unknown
suffixes are not qualified. Domain settings do not provision DNS or certificates.

After deploying schema175-compatible API and proxy binaries, a verified CP
administrator can use **Settings → App Access domains** to save the portal URL and
application base domain. **App Access → Configure domains** opens that same panel.
Both server processes read the saved database configuration without a restart;
environment values are the initial fallback before the first save. Domain lookups
fail closed on database/authority errors. Changing the default leaves existing
published hostnames and grants intact, so keep their DNS and TLS coverage. Update
SSO provider callback registrations before using a changed portal hostname. A
rollback to a binary older than schema175 must use a verified pre-upgrade backup
when saved settings exist; the down migration refuses to discard them silently.

Public browser TLS is published (loopback443 by default), and the gateway listener
8444 for remote gateways (see above). Gateway8444 and APIauthority8445 require raw
direct TLS and must not traverse the browser edge or an HTTP-terminating ingress. Public TLS is TLS1.3/HTTP1.1; ordinary WireGuard/control
listeners retain their compatibility settings. No inbound gateway listener is added.
The optional operator listener exposes unauthenticated fixed health/capacity gauges,
without application/user/URL/token labels: keep it private. Compose binds it to
container loopback; Helm exposes it only to kubelet probes on the pod port, with no
public or operator Service. `/readyz` requires a recent successful private authority
claim; it does not claim an application is published or reachable.

To share port443 between the portal and apps on one host, optionally set
`TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL` to the operator-managed HTTPS console
frontend, for example `https://console:8446`. Set
`TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_SERVER_NAME` when that listener's certificate
uses a DNS name different from its private service name. Public certificate roots
are used by default; `TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_CA_FILE` can name a mounted
public CA bundle for a private console CA. Verification cannot be disabled. The
upstream must serve the ordinary console and its public API, never the private
App Access authority or agent listener. It is fixed operator configuration and
cannot be changed by a browser request or domain-settings form.

This optional dispatcher reads current authenticated domain configuration and
sends only the exact configured portal authority to that upstream. Application
requests retain their exact publication/session checks. Console cookies, SSO
redirects and CSRF headers remain intact; caller-supplied forwarding/IP claims
are replaced with the proxy's observed HTTPS transport and peer. Keep the API's
immediate-proxy allowlist narrow. Existing separately exposed console routes,
including an operator's IP:9443 route, are unchanged and remain available when
the shared-listener domain authority is unavailable. With the setting omitted,
the public app listener behaves as before.

The customer owns DNS and TLS: configure the portal DNS record plus a wildcard
record for application prefixes, and certificates covering the portal and app
hostnames. For `internal.tunnex.app`, app coverage needs
`*.internal.tunnex.app`; `*.tunnex.app` alone does not cover those apps. A load
balancer may instead dispatch exact hostnames itself. If it terminates public
TLS in front of this listener, require HTTPS at the browser edge and re-encrypt
to the proxy with verified origin TLS. Do not trust arbitrary forwarded headers
or use an HTTP/skip-verification fallback. A successful settings save is not
DNS, certificate, or publication-readiness proof.

The separately retained named `app_restore` volume is mounted read-only by API and
proxy at `/var/lib/tunnex/app-restore`; it is outside PostgreSQL/Redis backups. Both
images preown this directory uid10001 mode0700. Recovery writes the shared marker
using the offline CLI, stops and inspects every API/proxy participant before restore,
then rotates authority and verifies readback before clearing it. The offline marker helper uses a private derived Compose snapshot that makes only that exact verified marker volume writable; serving mounts stay read-only. CLI volume overrides alone do not reliably clear a service read-only mount. The restore runner freezes validated effective Compose configuration in a private temporary snapshot so an override edit cannot switch its marker volume. The runner requires an explicit canonical local Unix Docker socket, ignores inherited remote Docker settings, and refuses helper database, secret-source, mount, or image changes relative to the inspected API. Helpers use its cached content digest without pulling. The archive is frozen privately and hashed before verification, and the held manifest is verified again before authority recovery (also on resume). No listener is restarted automatically.

Review first with:

```sh
python3 deploy/app-access/restore.py --docker-socket /run/docker.sock \
  --project PROJECT --directory CHECKOUT \
  --compose-file CHECKOUT/docker-compose.yml \
  --compose-file CHECKOUT/deploy/app-access/compose.yml \
  --dump BACKUP.dump --manifest BACKUP.manifest.json --operator NAME
```

Use the canonical existing socket path for your host (resolve symlinks first; the example uses Linux `/run/docker.sock`). Remote Docker endpoints are refused. Add `--apply` only after reviewing the dry run. Preserve a failed marker and use `--resume-marker UUID` with `--apply` to run fresh offline authority recovery without reapplying the dump. Never import a prior DB completion to clear a new marker. Recovery disables publications, revokes dedicated proxy credentials and advances every account app-auth epoch. Reprovision the proxy, obtain fresh logins and recheck/republish each intended app before opening browser access. Inspect stopped participant identities before intentionally restarting them. Store restore and raw manual marker deletion outside this procedure have no browser-authority qualification. These packaging files do not execute recovery.

Helm requires an existing shared restore PVC and API/proxy replicas1. Preprovision
its root uid/gid10001 mode0770 and its `app-restore` subdirectory uid10001 mode0700.
Both pods use that subPath with fsGroupChangePolicy OnRootMismatch so kubelet does
not recursively loosen the private subdirectory. TLS Secrets remain group-readable;
an init container copies only the proxy credential to a uid10001 owner-only0400
memory volume. Credential rotations require a controlled pod restart. The chart
does not generate CA keys, credentials or the PVC. Kubernetes restore/HA behavior
remains unqualified; the single-host restore runner does not validate it.

Proxy defaults limit public connections256, gateway channels/admissions128, authority
callbacks128, active requests256 and readiness operations8. Initial resource settings
are 1CPU/512MiB (Helm requests100m/128Mi); these are operator starting limits, not a
measured memory or throughput guarantee. SIGTERM marks draining, cancels workers,
closes outbound channels and gives HTTP servers up to5seconds before forced close.
No new admission occurs during shutdown. Already delivered data and completed origin
side effects cannot be recalled. Chunked request bodies remain unsupported; known-length
forms/uploads, SSE and WebSockets use the qualified bounded transport.

Operational measurements use fixed names and fixed histogram buckets, without
identity or topology labels. `connector_dial_failures_total` counts failed pool
Dial calls (including cancellation/timeouts); `upstream_roundtrip_failures_total`
counts transport failures before response headers, not origin HTTP error statuses
or post-header stream interruption. Successful response headers, including401/302,
record `upstream_response_header_seconds` from proxy dispatch to headers (pool wait
and gateway work included). `gateway_origin_response_header_seconds` is measured
at the gateway from registered-origin RoundTrip start to headers, including DNS,
connect and TLS, excluding body transfer. The connector overwrites the internal
timing header, the proxy validates a positive value up to60seconds and removes it before browser output.
Missing/malformed timing increments separate unavailable/invalid counters and is excluded from the histogram; sample count0 means no latency observation. Access decisions are unchanged.

Saturation counters observe rejected request/channel admission and unavailable
bounded authority callback slots. Notification counters distinguish dropped
full-queue events, failed callbacks and204 acknowledgements; an acknowledgement
alone does not prove a retained event. They measure bounded work queues, not TCP
buffer fullness or bytes already delivered. Capacity gauges plus these counters
remain readable only through the private operator listener; no telemetry buffer
or unbounded per-application series is created. Load measurements and actual
revocation/slow-consumer timing on the named deployment remain acceptance work.
