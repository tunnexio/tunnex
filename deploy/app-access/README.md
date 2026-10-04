# App Access operator composition

These files prepare an explicit opt-in deployment. The base Compose stack and Helm
charts keep App Access disabled. Ordinary installer reinstall and managed upgrade refuse an existing scoped App Access composition, including stopped participants, before replacing deployment files or restarting services. Use the explicit same-schema image replacement procedure below; it preserves signed proxy image pins, private authority configuration and the external restore volume. Ordinary managed upgrades and schema-changing opt-in upgrades remain unqualified. Enabling infrastructure does not grant entitlement,
opt in an organization, publish an application, or create a browser session.

Before installing or upgrading, verify the signed release descriptor with the trusted
`releaseverify -require-app-proxy -print-env -platform amd64` (or arm64). Use its
`TUNNEX_APP_PROXY_IMAGE` immutable digest; do not substitute a mutable tag. Older
signed releases remain usable without App Access, but cannot satisfy this opt-in
preflight. The existing protected CI release job now builds and signs the additional
image; no image has been published by this local work.

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

Only public browser TLS is published (loopback443 by default). Gateway8444 and
APIauthority8445 require raw direct TLS and must not traverse the browser edge or an
HTTP-terminating ingress. Public TLS is TLS1.3/HTTP1.1; ordinary WireGuard/control
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
