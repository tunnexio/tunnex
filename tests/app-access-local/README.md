# Local control plane and gateway

This owned Compose project runs the actual repository API and gateway binaries together, with an isolated PostgreSQL database, Redis, secrets volume, gateway identity volume and network. It publishes only localhost API `18083`, control `18446` and gateway health `19093`; the database and Redis have no host ports. It never uses the repository `.env` or existing Compose projects.

```sh
tests/app-access-local/prepare.sh
tests/app-access-local/run.sh up -d --pull never
tests/app-access-local/verify.sh
```

Preparation uses existing Go module/cache dependencies with `-mod=readonly`, chooses the Docker daemon architecture, writes random local credentials under ignored `.runtime/` with restrictive permissions and records HEAD plus binary SHA-256 hashes in `.runtime/build.txt`. No credentials belong in tracked evidence or user-facing output. The bootstrap password appears in the API's private first-boot logs; do not publish those logs.

The API bootstraps one owned organization and gateway grant using its existing installer bootstrap contract, then migrates only its owned database. Gateway enrollment uses the real public API and its subsequent control traffic uses real mTLS. The cached `tunnex-gateway-qualification:local` image supplies networking tools; the current repository gateway binary is mounted into it. This local prerequisite must already exist; `--pull never` prevents remote image retrieval. The gateway has NET_ADMIN only inside its own namespace, creates a real WireGuard interface and owns that namespace's firewall. It does not alter host interfaces. AI auto-setup and AI provider management are explicitly disabled. Flow observations are disabled for this transport scope.

Restart only this owned gateway to repeat retained-identity reconnect:

```sh
tests/app-access-local/verify-reconnect.sh
```

An early memory-backend attempt enrolled successfully but failed ownership startup because current gateway startup still requires a real interface/firewall. The final harness uses `wgctrl` and idempotent interface initialization. No readiness bypass is used.

On 2026-10-03, the final AA-1 API reported healthy, gateway reported ready, schema readback was version 167 with dirty=false, and node readback showed one active enrolled gateway, advancing heartbeat, `egress_nat=true`, and `ai_vpn_http_ready=false`. A gateway restart reused its node ID, certificate serial and key fingerprint. This proves existing enrollment/control readiness and reconnect in the isolated stack. It does not prove App Access proxying, app authorization or VPN client traffic; those require their own story acceptance checks. Empty policy version 0 is not App Access delivery proof.

Leave this stack running for development. Any later shutdown must address this exact project; volume deletion is a separate deliberate action. Never use a generic repository `docker compose down` or delete shared volumes.

All Docker operations pin the local Colima Unix socket and clear inherited Docker context/TLS variables. The ownership guard directly inspects every exact external network/volume name, including resources hidden by foreign or missing project labels. It rejects foreign project/checkouts, changed recorded identities and missing previously recorded resources; preparation creates only absent first-run resources. Project containers must have this Compose working directory. Copying a runtime marker to another checkout fails. Retained resources from this lane were recorded during the guard upgrade without deleting or replacing them. New resources carry checkout labels. External Compose declarations prevent label reconciliation from replacing retained data. Verification asserts the database target, one clean migration record, exactly one active gateway with fresh heartbeat and unexpired certificate. Reconnect verification restarts only that gateway, asserts unchanged node ID, certificate serial and key fingerprint, and waits for a post-restart heartbeat.

Run registry/grant/connector database acceptance independently with `tests/app-access-local/verify-registry.sh`. It compiles a Linux test binary, uses the pinned local daemon/network, creates a uniquely named disposable database, migrates through historical version 166 and new versions 167–169, validates registry/grant/connector boundaries and audit transactions, and removes only that child database. It leaves the active control plane database unchanged. Unit-only runs skip that integration test unless explicitly enabled by this owned harness.

Browser review uses a separate verified human fixture account created by the gated `prepare-ui-account.sh`; bootstrap credentials remain intact. Native Community API on 18083 proves entitlement denial and retained inspection. `run-browser-fixture.sh` starts a gated test-only HTTP router on localhost 18084 with ephemeral signing keys, the owned PostgreSQL and Redis database 1. It installs no licence into the native CP. Pair Vite previews with 127.0.0.1:15173 for native API and localhost:15174 for the fixture; distinct hostnames isolate cookies across ports. The paid fixture exercises real draft, grant and connection-check handlers; it is not a production licence or app-content proxy. Its `--stop` mode validates the exact process and ownership labels, then removes only that ephemeral container.

AA-3 development adds a restricted mTLS app-control fixture on loopback `18447`,
using the existing owned CA and gateway certificate identity. It reads the retained
API master key from the owned API-state volume mounted read-only, refuses CA creation,
and mints its server leaf in memory. Ordinary VPN control stays on `18446`.
The owned gateway uses `TUNNEX_APP_ACCESS_CONTROL_URL=https://app-access-fixture:18447`;
the production default remains its ordinary authenticated control endpoint.
The ephemeral signed entitlement is confined to this fixture and is never installed
in the native Community control plane.

`run-origin-fixture.sh` starts a local test HTTP/HTTPS origin with no host ports,
only on the exact owned network. `prepare.sh` builds its binary. It generates
private keys in memory and writes only the public CA to ignored
`.runtime/origin/origin-ca.pem`. Obtain its current network address from the exact
owned container before authorizing its `/32` in a test draft; never use a blanket
private-network exception. Its two registered origins are
`http://origin-app-fixture:8081` and `https://origin-app-fixture:8444`.
These are local integration prerequisites, not deployed customer applications.
The origin fixture's `--stop` mode checks its exact project, checkout and fixture
labels before stopping only that process. Retained volumes are never deleted.
