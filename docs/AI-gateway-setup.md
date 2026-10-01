# Customer-owned AI gateway

Hosted releases that declare the bundled AI engine install it with Tunnex Server.
There is no separate Compose add-on for these releases. The backend starts with
no providers, models, grants or inference requests. Organization access remains
disabled until an administrator enables it.

The engine is the signed Tunnex Bifrost image built from the pinned upstream Go
source, with Tunnex's private connection-test extension. Provider credentials and
scoped inference keys stay in its encrypted database. Provider tests run inside
the engine.

The published signed v0.1.34 release does not declare the bundled engine. The
setup described here requires a newer signed release containing `images.ai-engine`
for both supported architectures and the matching public installer.

## Install once

Run the normal verified Tunnex installer and select a real HTTPS public URL.
The installer prepares the private backend, generates its administrator
credentials and durable encryption key, and records the signed image digest.
These secrets are stored in the protected installation configuration and are
never printed. Keep them with encrypted backups.

Setup also creates an authenticated private CONNECT proxy using the signed API
image's egress helper. API and engine share its read-only destination policy.
Public HTTPS on TCP443 is permitted; private, metadata, local, and protected
control-plane destinations are refused. Upstream TLS verification stays enabled.
The policy protects the installation's real control-plane hostname or address.
Private or custom destinations require an explicit operator policy review.

The generated `ai-egress-policy.json` is stored beside `.env`. Reinstallation
keeps the proxy credentials and existing policy. A configured missing policy,
partial credentials, or an unfamiliar operator proxy requires repair or a
reviewed migration; setup does not replace those settings silently.

Plain HTTP evaluation still installs the backend, but AI configuration and access
remain unavailable by default. Use HTTPS, or the explicit restricted-network
policy below. VPN setup remains available.
Do not substitute localhost or merely change the URL scheme: workload receipts
and signed assertions use the actual public origin.

Older signed releases without the bundled-engine declaration retain their
original installation behavior. Installing such a release does not add the
backend. Use a release with the bundled-engine capability rather than applying
unmatched deployment files to an older control plane.

## Optional private HTTP policy

`TUNNEX_AI_ALLOW_PRIVATE_HTTP` defaults to `false`. An installation administrator
may explicitly set `TUNNEX_AI_ALLOW_PRIVATE_HTTP=true` only after verifying that
the real control-plane origin is restricted to a trusted private or VPN network.
Set `APP_BASE_URL` to that exact tested origin; workload receipts and assertions
use it. The installer
accepts the origin through `TUNNEX_PUBLIC_BASE_URL`.

The option does not detect a VPN, classify an address as safe, configure a
firewall, or infer permission from request headers or a client IP. The operator
owns the network restrictions and must verify both permitted access and rejected
public access before enabling it.

The review sandbox illustrates one bounded design: the public port-80 listener
unconditionally rejects AI routes, while the full console is published only at
`172.31.20.253:8082`. No security-group rule permits TCP `8082`, the instance has
no IPv6 address, and an enforced gateway rule permits only the owner's exact
device `/32` to that private destination and TCP port through `wg0`. Verify the
client's native tunnel route, the private console response, public-port refusal,
and public AI-route denial even with spoofed forwarding headers. Merely binding
to a private address is insufficient evidence.

This policy changes only the accepted control-plane HTTP origin. Authentication,
encrypted provider storage, workload proof checks, organization opt-in, model
grants, and provider upstream TLS validation remain required. Provider keys and
inference are still separate explicit setup steps; enabling this policy sends no
provider request.

## Connect a provider

1. Open **AI Gateway → Models & endpoints → Add Model**.
2. Choose a provider or saved credentials, then choose exact models and modes.
3. Enter a provider key only when adding or replacing credentials. **Test Connect**
   makes a small inference request and can incur a provider charge; installation
   never performs this test for you.
4. Save after a successful test and wait for **Applied** state.
5. Enable organization access in **AI Gateway → Settings**.
6. Grant the model to a user group under **Access**, or configure a workload.
   Provider credentials alone grant no user or workload access.

**Test Connect** is available once required fields and endpoint syntax are valid.
Network readiness is reported by the test, rather than disabling the button.
Missing installation egress returns `503`; a denied endpoint returns `403`;
disabled or unapplied saved credentials return `409`. These refusals send no
provider request. Provider authentication, model entitlement, and upstream errors
are reported after an allowed request. Adding a model still needs a successful test.

Administrators with `policy:manage` can choose **Create user group** inside the
grant dialog. Creation keeps the model selected and selects the new group;
granting access remains an explicit next action.

People use **Playground** with their Tunnex login. Applications use the workload
flow in [Workload model access](workload-model-access.md). Managed agent runtimes
retain their existing team policies and assignments.

Catalog checks read available model metadata; they do not prove inference access.
A provider account can expose a model in its catalog while refusing requests to
that model. Usage and cost are observed estimates; daily thresholds are soft
admission limits and concurrent requests can exceed them.

## Verify the installation

The installation administrator can use the existing project and configuration:

```sh
docker compose --env-file .env -f tunnex.yml ps ai-egress bifrost api
docker compose --env-file .env -f tunnex.yml exec -T bifrost \
  wget -qO- http://127.0.0.1:8080/health
docker compose --env-file .env -f tunnex.yml exec -T ai-egress sh -c \
  "wget -S -O /dev/null http://127.0.0.1:8190/ 2>&1 | grep '407 Proxy Authentication Required'"
```

The engine and egress proxy have no published host ports. Only the API, engine,
and proxy share the AI network. The proxy also joins the application network to
resolve and protect internal service addresses. The local `407` proves the proxy
listener requires authentication, without sending inference or displaying secrets.
Administrator and inference endpoints require authentication. A healthy backend
alone does not prove a provider key, model entitlement or grant works.

If the console reports an HTTPS prerequisite, configure the actual TLS endpoint
and matching public origin, or complete the restricted-network checks before
explicitly selecting private HTTP, then rerun normal setup. Keep the existing
project name, encrypted engine storage and encryption key. Do not reset volumes
or substitute a false origin to make a status card green.

## Test a fresh bootstrap

Use a separate clean VM with a reachable HTTPS hostname. Direct HTTPS on a
public IPv4 address also works with a signed release containing
[public-IP HTTPS support](S-public-ip-https-decisions.md); v0.1.36 and older
do not include that edge configuration. Keep TCP 443 public for certificate
issuance and renewal. Follow the normal verified installer flow; do not copy
newer Compose files into an older installation.

1. Complete installation without entering provider keys. The three services
   above should be healthy, with no host ports for the engine or proxy.
2. Open **AI Gateway**. It should contain no providers, models, or grants, and
   organization access should be disabled.
3. Open **Add Model**, choose Azure or another provider, and enter valid required
   fields. **Test Connect** should be enabled. Selecting it is the first explicit
   inference check and can incur a provider charge.
4. Re-run the same installer with the same installation directory and project.
   Confirm the existing engine state, durable key, proxy credentials, and policy
   survive; do not delete volumes or print `.env` while checking.

For a local source check without creating a VM or contacting a provider, run:

```sh
sh deploy/install-host-bootstrap_test.sh
sh deploy/upgrade_apply_contract_test.sh
python3 deploy/hosted-ai-compose_contract_test.py
sh deploy/byodb-install-contract_test.sh
```

The installer and upgrade tests execute the actual scripts with command fixtures;
the Compose tests render the actual hosted configuration. They cover fresh setup,
repeat setup, earlier engine-only configuration, policy and credential
preservation, refusal cases, and external databases. These checks do not replace
a clean-VM installation of the published signed release.

## Preserve state during upgrades

Normal hosted upgrades include the backend and its signed image pin. Reinstalling
preserves existing managed configuration and credentials. Incomplete credentials
or retained encrypted storage without its matching key block setup before a
replacement key is generated. File-managed provider installations require a
reviewed transition; startup configuration must not remove existing keys.

The v0.1.34 host updater predates AI bootstrap. Its first dashboard upgrade to a
release requiring the engine cannot prepare the new settings; replacing its
helper on disk does not update the process already running. Do not use an
automatic retry as the migration procedure. For the first transition, retain
verified database and configuration backups, then use the new verified installer
in the same directory and project during maintenance. Its rerun path preserves
existing database credentials and prepares the bundled engine, egress policy,
and updated host helpers. Check the actual public origin and any operator-managed
AI configuration before proceeding. Subsequent upgrades use the updated helper.

The `ai_engine_config` volume holds encrypted provider configuration and scoped
key state. `ai_engine_logs` holds accounting metadata. Content logging is disabled
in the managed bootstrap configuration; metadata retention defaults to seven days.

Before replacing an existing bundled engine, the updater stops it briefly,
snapshots both volumes, and restarts the original engine before continuing.
The private backup directory retains the snapshot, matching environment file and
engine configuration, and the existing egress policy alongside the PostgreSQL
backup. Snapshot failure blocks replacement and restarts the original backend.
Protect these files as secrets.

Disable organization access to refuse new requests. Accepted requests retain
their bounded completion window. Stopping the backend preserves state; deleting
volumes or changing the encryption key is not an upgrade or rollback procedure.
A downgrade can require restoring a matching engine/database backup.
