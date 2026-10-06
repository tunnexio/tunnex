# Server Access packaging and mixed-version qualification

Local results on 2026-10-05, Community baseline. These changes use the existing Docker installer and Helm charts. No release, remote deployment, Kubernetes cluster, bucket or filesystem mount was created.

## Shipping configuration

New installer environments persist `TUNNEX_SERVER_ACCESS_ENABLED=false` by default. Explicit `true` is validated and persisted; rerunning the installer preserves the existing environment and durable keys. The shipping Compose passes the flag to both API and node-agent. A separately installed gateway must also set its runtime flag; the CP flag alone does not enable an old or disabled gateway.

The CP and gateway Helm charts expose `serverAccess.enabled`, default false. The CP rejects enabling Terminal with `api.replicas != 1`: terminal sessions are bound to one API process and do not implement HA or resumption. The existing Recreate strategy avoids overlapping process ownership. Default-off deployments can retain their existing replica settings.

The canonical Compose mounts a dedicated persistent `server_access_recordings` volume at `/var/lib/tunnex/recordings`, so its mount survives normal installer/dashboard upgrade replacement. By default its name follows the installed Compose project. For an already mounted customer filesystem/EFS/EBS, prepare a Docker bind-backed volume separately, grant UID10001 the required access, and persist `TUNNEX_SERVER_ACCESS_RECORDING_VOLUME=<existing-volume>` plus `TUNNEX_SERVER_ACCESS_RECORDING_VOLUME_EXTERNAL=true` in the installation `.env`. Docker refuses a missing external volume. Select `/var/lib/tunnex/recordings` in Terminal Settings. The API image initializes its recording directory as10001:10001 mode0700, separately from secret/key custody. External-volume configuration does not create that volume or mount EFS/EBS.

`deploy/server-access-storage.override.yml` remains an optional manual bind alternative, requiring an existing source and `create_host_path:false`. Its extra Compose file must be included manually on every applicable operation; ordinary installed upgrades do not preserve that additional override. Prefer the canonical external-volume settings for installed customer deployments. CP Helm optionally mounts `serverAccess.recordingVolume.existingClaim` at the same path and sets fsGroup10001. PVC/storage provisioner creation remains external; object storage needs no recording PVC.

Both shipping edge configurations now explicitly upgrade only the terminal WebSocket route with HTTP/1.1, Upgrade/Connection, disabled buffering/cache and bounded timeouts. Location-level headers repeat the validated Host authority and trusted original scheme because nginx does not inherit server proxy headers when a location defines its own. This preserves exact browser Origin checks, including non-default ports.

## Executed gates

| Gate | Result |
|---|---|
| Full installer command-stub contract | PASS, including fresh default-off, explicit true, invalid value refusal and byte-identical environment preservation on rerun. No host Docker installation or network request occurs through real commands. |
| `packaging-qualify.py` | PASS: Compose JSON and both Helm charts render defaults/opt-in, persistent/default/external recording volumes, existing bind/PVC and single-API fence; disabled two-replica CP still renders. Synthetic settings only, no real `.env` read and no deployment. |
| Installed upgrade command-stub contract | PASS; Terminal enablement and external recording-volume name/flag survive environment rewrite. Negative backup failures are intentional test cases. |
| Non-root named volume | Exact pinned API Alpine runtime and source directory setup: inherited UID10001/mode0700; actual filesystem durability/isolation/symlink tests pass as non-root with TMPDIR on a fresh owned named volume. |
| Docker nginx | Pinned unprivileged nginx 1.30.5 configuration syntax PASS; actual terminal 101 and executed `EDGE_WS_OK héllo` through port 18335 PASS. |
| Rendered Helm nginx | Exact Helm-rendered public config syntax PASS; actual terminal 101 and executed UTF-8 command through port 18336 PASS. Local `web` DNS placeholder supplies no frontend/cluster qualification. |
| Base gateway → new API | Built untouched base `435b4d53900c768073a49dbcc72579567fcdc524`. Existing gateway readiness remained HTTP 200; after the 10-second terminal runtime observation expired, new admission returned `403 gateway_terminal_unavailable`. |
| Restore current gateway | Same persisted enrolled identity/state; current binary resumed capability observations and executed a new real SSH command. Existing terminals cannot resume. |
| Base API rollback → schema 185 | Fresh `sa_mixed_version_185` contains copied DDL only and a synthetic migration version row, no baseline user data or keys. Base API exited before serving; a diagnostic using the base migration package confirmed unavailable migration 185 and schema remained 185 clean. The old startup logger redacts this as a generic database failure, so diagnosis requires the explicit schema/binary check. |

API/gateway final rebuilt hashes remain those in integrated evidence; adding qualification tests and packaging did not change executable backend content. The base gateway SHA256 is `473156849dae0eb0150d02157d7bdf89f425639202406e2a40a16f6c31ff4c3f`.

## Upgrade and rollback order

1. Back up database and separately custodied installation master plus external recording objects. Validate in an isolated restore target, as described in [recovery qualification](SA-recovery-qualification.md).
2. Keep Terminal organization admission disabled while aligning CP, edge and gateway binaries/configuration. Run schema migrations with the matching binary; preserve node enrollment and key volumes.
3. Enable the runtime flags, wait for fresh authenticated gateway capability, verify pinned host trust and each account's readiness, then explicitly enable the organization and grant access. An old/disabled gateway fails closed rather than accepting a terminal assignment.
4. Before rollback, disable admission, end terminals and allow independent leases to withdraw. Keep storage snapshot credentials through retention. An older API cannot serve a newer unsupported migration version; disabling the flag alone is insufficient for database downgrade.
5. Use only reviewed migration rollback conditions or a validated coordinated backup restore. Storage migration rollback refuses to orphan external destinations. Do not downgrade underneath live listeners or replace the installation master. Do not promise restored terminal resumption.

The local fixture retains the empty rollback database, stopped old-API/probe containers and owned edge proxy containers for inspection. The baseline CP/gateway/SSH target remains healthy. No cleanup or external rollout is implied. Fresh customer-host installation, actual Kubernetes rollout, mixed production fleets, cloud IAM, mount permissions/stalls and HA need their own environment-specific qualification.
