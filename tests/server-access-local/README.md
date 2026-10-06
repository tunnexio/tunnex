# Owned local browser SSH feasibility lane

Nonshipping SA-0 harness on feature/browser-access. Actual API/node enrollment; isolated PostgreSQL/Redis/network/state; disposable Linux SSH fixture; optional one-shot outbound mTLS broker. All Docker calls pin `/Users/pawangupta/.colima/default/docker.sock`. No AWS or remote runtime. Ordinary port bindings are loopback only. The scripts refuse foreign project/checkouts/resources; no cleanup/down mode is offered.

From repo root:

```sh
tests/server-access-local/prepare.sh
tests/server-access-local/prepare-ssh.sh
tests/server-access-local/docker-local.sh build -t tunnex-sa0-tools:local -f tests/server-access-local/Dockerfile.tools tests/server-access-local
tests/server-access-local/run.sh up -d --pull missing
tests/server-access-local/verify.sh
tests/server-access-local/pin-target.sh
python3 tests/server-access-local/linux-boundary-probe.py
tests/server-access-local/run.sh exec -T gateway python3 < tests/server-access-local/linux-pty-probe.py
tests/server-access-local/run.sh exec -T gateway python3 < tests/server-access-local/primitive-probe.py
tests/server-access-local/prepare-broker.sh
tests/server-access-local/run.sh up -d --pull never outbound-broker
tests/server-access-local/run.sh exec -T gateway python3 < tests/server-access-local/outbound-gateway-probe.py
tests/server-access-local/run.sh logs --no-log-prefix outbound-broker
```

prepare.sh uses cached Go 1.26.8 directly and refuses missing modules/toolchain rather than downloading; override SA0_GO with an equivalent installed binary. Image pulls and apk packages populate only the fresh local Docker environment. A fixture account named fixture is explicitly provisioned in the disposable image, with password authentication disabled in its SSH daemon; product OS provisioning remains out of scope. SSH has no host port. prepare-ssh signs a five-minute client certificate; refresh it before repeating PTY tests. Boundary probes issue their own short-lived client certificates and leave keys only in ignored private runtime directories.

CA signing key stays host-side under .runtime/ssh; gateway mounts .runtime/ssh-client; target mounts only .runtime/ssh-public and its start script; broker mounts only its script/TLS state. Public host-key pin comes from independently controlled exact owned target, never ssh-keyscan auto-trust. Fixture principals/actor names are synthetic; they are not product authorization. Broker pins the already enrolled gateway certificate and uses a separate fixture server TLS trust; restart prepare-broker after gateway rotation. A new run of an exited one-shot broker is explicitly started by run.sh up.

Actual local API: http://127.0.0.1:18183. Control mTLS: loopback 18546. Gateway readiness: http://127.0.0.1:19193/readyz. Frontend development preview: http://127.0.0.1:15195, API proxy through TUNNEX_DEV_API=http://127.0.0.1:18183. It currently uses worktree symlinks to existing cached web dependencies; do not install through those symlinks or change their shared targets. Integrated development must use an isolated dependency installation. CP bootstrap credentials appear in private first-boot logs; never publish logs/env/key files. The initial admin requires the normal password-change journey.

Runtime secrets, binaries/results and manifests are ignored. Preserve volumes while developing. Any cleanup must identify this exact local project and requires the user's requested cleanup scope. No generic repository Docker cleanup, shared-service restart, commit/push or deployment is implicit.

[Contract](../../docs/SA-0-authority-contract.md) and [evidence/limits](../../docs/SA-0-development-evidence.md).

### Final recording feasibility review

`sh tests/server-access-local/recording-review.sh` runs seven nonshipping primitive probes in a new networkless read-only container. A dedicated 64 KiB tmpfs proves real ENOSPC closure before output forwarding; a separate 1 MiB /tmp supports the other probes. It uses the owned target image and removes only the new disposable probe container. This does not qualify encrypted product recordings or browser replay. See the final acceptance matrix in the evidence record; SA-0 contracts are technically accepted for the authorized local POC after the explicit human decision amendment; integrated and production acceptance remain separate.

## Integrated terminal and customer storage

The later integrated build has real Browser Access → Terminal, normal local MFA users, account grants, a pinned OpenSSH target, optional encrypted recording and Observer replay. See `../../docs/SA-integrated-development-evidence.md` for measured results and qualification limits. The product flag remains default off; this owned fixture explicitly enables it for Community.

`prepare.sh` creates the private runtime recording mount and local emulator dummy credentials once. API mount `/owned-recordings` is a dedicated owned local volume; Advanced compatibility settings can test/save it and legacy S3-compatible, Azure Blob and GCS connections. All new recording payloads use PostgreSQL with the 30-day default; separate S3 archive settings control expiry archiving and retain saved credentials for manual export when automatic archival is OFF. EFS/EBS paths must already be mounted on the control plane; no cloud resources are provisioned.

Compose includes pinned Moto S3 and Azurite Blob fixtures sharing the API network namespace. Only literal loopback HTTP is allowed under the fixture's explicit development-only storage flag. The API host publishes loopback ports18333(S3) and18334(Blob) for owned emulator bootstrap; no cloud credentials are used. `run.sh up -d recording-s3 recording-azure` starts them. Recreate emulators after recreating the API so their shared network namespace is current. Moto bucket state is ephemeral. Before a runtime recreation, preserve the exact owned encrypted objects and a hash manifest privately, then restore and verify them before historical replay checks. Do not claim the emulator qualifies object-provider durability.

Runtime secrets and test login credentials are ignored/private. Do not publish `.runtime`, export private CA keys, adopt another Compose project or wipe volumes. All work remains uncommitted and the owned fixture stays running for local review.


## Completed operational continuation

`python3 tests/server-access-local/packaging-qualify.py` renders synthetic Compose/Helm defaults, opt-in, persistent/external recording mounts and the single-API fence. It requires prepared `.runtime/`, Helm and the explicit local Docker socket; it does not deploy. It writes only a public rendered chart proxy configuration. `deploy/install-host-bootstrap_test.sh` and `deploy/upgrade_apply_contract_test.sh` use command stubs and qualify preserved Terminal/external-volume settings without external changes.

`proxy.override.yaml` runs the shipping Docker and exact rendered chart proxy on loopback18335/18336. `nonroot-volume.override.yaml` qualifies actual filesystem storage tests as UID10001 on a fresh project-owned named volume, using the API Dockerfile's exact directory setup and pinned runtime base. `mixed-version.override.yaml` changes only the owned gateway executable to a separately built base revision; restore the ordinary gateway definition afterward. `mixed-api.override.yaml` is an empty schema-only rollback target; never substitute the serving database or existing installation keys.

For these overrides, use the same explicit project and `--project-directory "$PWD/tests/server-access-local"` with the baseline Compose first and the chosen override second. Run `run.sh ps` first for checkout/resource ownership checks. Do not use remove-orphans: stopped probes and revoked identity evidence intentionally remain.

Identity qualification retains exactly documented revoked nodes/three inert audit organizations because deletion conflicts with immutable audit records. `verify.sh` permits only those exact known identity tuples in addition to the original active gateway; no prefix-based trust or audit-trigger bypass was added. Capacity actors were logged out/deactivated and grants/memberships revoked. [Integrated evidence](../../docs/SA-integrated-development-evidence.md) links signedSSO, browser, recovery and packaging proof; physical devices, customer cloud/mounts and production HA remain environment-specific.

## PostgreSQL-first archive lifecycle

Schema186 preserves existing expiry and destination snapshots. New recordings commit encrypted output/timing/resize to PostgreSQL before forwarding. At expiry, unarchived recordings lose payload/key but retain metadata; configured automatic S3 jobs retain the source until verified. Manual export is authorized independently of automatic archival and retains PostgreSQL until expiry. Deterministic object keys, durable bounded progress and retry cooldown support restart/failure recovery. A complete encrypted manifest includes wrapped data key, count, digest and incomplete flag. Archived recordings require their original sealed connection and installation key for authenticated replay. Include archived objects in recovery planning; database-only backups do not capture external payloads.

### Encrypted archive portability within the installation

New S3 archives include `recording-v2.tunnex-recording`, a verified self-contained encrypted package. Sessions → Import recording accepts this package and authorized Manual download JSON. Package upload requires explicit confirmation and current organization Replay permission plus original owner or SessionManage authority. It can replay after original session/recording deletion without restoring audit identity. The originating installation master remains necessary; no key is exported or plaintext silently substituted. Raw historical chunks/manifests remain server-replay formats and are not import files. Limits are 32 MiB per import package, 4096 events and 16 MiB captured encrypted payload; ordinary HTTP/chunk limits remain unchanged.
