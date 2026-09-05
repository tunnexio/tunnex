# C5 follow-up — builds, gates and private application prerequisite

Observed 2026-09-05, through 14:49 UTC. This records preparation and local
substitutes, not a successful new gateway or desktop VPN walk.

## Immutable candidate

Clean detached source: `61ecc5fec4e5a971faaf9b1c65ccdc7b3b4cd8c1`.
Version: `0.0.0-walk.sha61ecc5fec4e5a971faaf9b1c65ccdc7b`.

All six Linux/amd64 runtime images, four reproducible charts, Linux CLI and
native Darwin CLI were built. Both executed CLI version checks and all six
original bundle checksums passed. The manifest SHA-256 is
`65fb29b7feb05d6f5bf3a800121996b20d0176dd30e289add2da330fcb636500`;
native CLI SHA-256 is
`fadaf6d023f76b57583d001c6a54a064c46f062c3e238d1218bf9aac072dbf5f`.

**New candidate publication is BLOCKED, not complete.** Two upload requests
were rejected before execution by approval review. The user replied to an
exact payload/destination approval question, but the second reviewer still
required standalone trusted wording. That specific wording was requested;
no alternative publisher or transfer was used to bypass the rejection.
Manifest registry references currently name local-built immutable IDs only;
AWS digest verification and authenticated chart-pull comparison are pending.
The existing CP still runs the earlier d2 candidate with its valid Scale license.

## Fresh additional gates at this source

In a separate clean clone, with explicit task Docker endpoint and
`COMPOSE_PROJECT_NAME=tunnex-s205-aws-20260905a`:

- `make test-cli`: PASS (build, vet and all CLI packages).
- `make test-operator`: PASS (build, tests and no-DB-import census).
- `make test-helper`: PASS.
- `make helper-crosscompile`: PASS Darwin amd64/arm64 and Windows amd64,
  CGO disabled for these compile checks.
- `make test-k8s-charts`: PASS all six packaging/chart contracts.
- Web typecheck, 110 test files / 1,377 tests, and production build: PASS.
- Desktop typecheck, 292 tests, build and package: PASS.

Node normal/race gates and the bounded independent C5 review are recorded in
`c5-startup-node-gates.md`. These results do not replace the remaining API,
generation, migration, both-edition and final-SHA CI obligations. GitHub returned
zero check runs for pushed `61ecc5f`; zero is not green.

## Matching desktop package

Universal macOS package was built from the same clean source with Go 1.25.13,
native CGO helper, and explicit Electron 39.8.10. Its manifest reports the exact
candidate version. SHA-256:
`34e121ab0ac69ecb7b6a6a57c0910220ab39f26c156e7ab3adefe9c66a668c91`.
Staged helper SHA-256:
`0e59ec07c965cc431d91ec58a6063bbfbee14319bd06dc7ad97037c7ff66ca67`.
The package is unsigned/unnotarized, not a public release.

Installation of this exact package is not established. The user was given its
local link; macOS requires their administrator authentication. No password was
requested in chat, no helper was replaced by the agent, and no manual VPN route
was installed. Current installed-app readback was a different version, 0.1.1,
with helper source `7c0edcf6606f747d705d02433f8ac42becdfbc40`; it must not be
counted as the candidate. Native screenshot capture failed with a macOS capture
error. Browser dashboard access was separately confirmed after the user logged
in; the cluster form was inspected and canceled without registration.

## Private application fixture

The source-controlled fixture is `private-service-fixture.yaml`. AWS account,
principal, cluster ARN, ACTIVE state and exact task VPC were verified again.
The previously absent namespace `tunnex-s205-workloads` was created with only
the fixture ConfigMap, two-replica Deployment and ClusterIP Service. No extra
EC2 instance, public listener, credential, host mount or service-account token
was introduced.

The first fixture revision (`460d22e`) failed because stock Nginx attempted
`/var/cache/nginx/client_temp` on its read-only root filesystem. Source correction
`a05ec44` directs all cache paths into the existing bounded `/tmp` volume and
references a new versioned application ConfigMap. Ordinary declarative apply
then rolled out that application template; no Tunnex object, host network,
CNI, Secret or PVC was patched and no remedial rollout-restart was used.
The original application ConfigMap remains retained. This is pre-walk fixture
setup, not zero-touch recovery acceptance.

Resolved official Linux/amd64 Nginx manifest and actual pod image IDs match:
`docker.io/nginxinc/nginx-unprivileged@sha256:ee1643aef6b99d1058aa79b74679ba3e63094a98a1144a4326def7bae77d293b`.
Registry metadata identifies 1.30.4-alpine and official source
`nginx/docker-nginx-unprivileged`.

Readback:

- Deployment: 2/2 Ready, both containers running with zero restarts.
- Service: `172.20.37.36:8080`, ClusterIP only, no external IP.
- Pod UIDs: `d6facbbd-832d-40d5-a419-37f3b4d806fd` and
  `d9b9329b-a6f0-4b0c-bc97-9c90e40e48cc`, on workers 10.240.10.121 and
  10.240.10.204 respectively.
- From the unprivileged application pod, both direct Service IP and
  `s205-private-nginx.tunnex-s205-workloads.svc.cluster.local:8080` returned
  `S20.5_PRIVATE_SERVICE_OK`, exit 0.

These two HTTP results establish native in-cluster application/DNS health only.
They are explicitly **not** local-desktop-through-Tunnex proof. No fresh A2/B
gateway, cluster registration, connector pool, HA activation or desktop Service
access has passed for the new candidate.
