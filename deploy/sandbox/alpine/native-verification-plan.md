# Remaining native verification — bounded, not executed

Local blocker: Mac has no Podman/newuidmap/unshare toolchain. Docker reports
rootful Linux/aarch64, seccomp/cgroupns, no rootless/AppArmor security option.
Docker emulation cannot satisfy the provider's required
`podman info --format '{{.Host.Security.Rootless}}' == true`. No host software,
subuid settings, services, policies or machines were installed/changed.

Trigger: parent-approved qualification on an already provisioned Linux host of
matching architecture, with the existing dedicated worker UID1101 and subordinate
200000:65536 mapping and AppArmor profile. If those prerequisites are absent,
stop and obtain separate setup approval; do not silently install or alter them.
Keep all product org/template creation gates closed. Reconcile profile choice
first; initially qualify Minimal only. Other candidates are preserved, not activated.

Bounded run: one isolated fixture database named `tunnex_sandbox_qual_<unique>`;
one fixture org, one retained sandbox maximum, one CPU, 128 MiB RAM, 64 PIDs,
256 MiB task-only aggregate ext4 workspace/assets backing, 900-second TTL.
No host ports, privileged workloads, ambient runtime sockets or human secrets.
Maximum 15 minutes per image; stop on first failure and remove only owned state.
Serial runs on native arm64 and amd64 hosts are required; no emulation counts.

1. Read host arch, rootless status, uid/subuid mappings, AppArmor enforcement,
   cgroup controllers and the task-specific 256 MiB mount. Save public outputs.
   Refuse a host that differs from approved worker/setup identity. This is read-only.
2. Transfer the selected task image export only. `podman load --input <task export>`
   under the worker identity; `podman image inspect <config_digest>` must match the
   manifest config, architecture, uid1001 and fixed Bash CMD. Native measurement
   must record actual imported image digest and allocated storage separately.
3. Build worker/runtime/probe from the selected clean commit (no host install):
   `CGO_ENABLED=0 GOOS=linux GOARCH=<arch> GOFLAGS=-mod=readonly go build -p=2`
   for `apps/api/cmd/tunnex-sandbox-worker`, `tunnex-sandbox-runtime` and
   `tunnex-sandbox-ssh-probe`. Hash staged binaries. Reuse the reviewed task-only
   units and exact paths in `deploy/sandbox/qualification/README.md` after parent
   approval; do not start arbitrary parallel workers.
4. Seed the isolated DB with `tunnex-sandbox-fixture-setup` using stdin JSON:
   database_url for the fresh qualification DB, fresh master_key/login_password,
   exact measured config_digest as image_digest and private output_directory.
   It refuses product DB names. Keep all generated keys/configs private and only
   record public identifiers. This task does not execute that provisioning.
5. Start the approved fixture worker with
   `--fixture-config=/var/lib/tunnex-sandbox-qual/worker/config.json` under UID1101;
   use the existing network helper and exact approved gateway identity. The
   provider must create with `--pull=never --network=none --cap-drop=ALL`,
   no-new-privileges, uid1001, read-only root, keep-id mapping and trusted mounts.
   Capture inspect output to prove actual mounts/caps/cgroups and no host publish.
6. Require real policy acknowledgements, canonical gateway/network state and
   pinned SSH probe before Ready. Through that private fixture connection perform
   uid1001 check, exit37, Unicode plus 1 MiB binary SFTP byte-for-byte/hash roundtrip,
   wrong host pin rejection and static-bootstrap execution. Record actual idle
   cgroup sample with method/date/caps; do not substitute Docker's values.
7. Write a task marker to /workspace, stop/start through lifecycle, then restart
   worker. Marker and external host key must persist. New network epoch must
   rerun policy/SSH readiness; force a probe/network failure and assert Ready is
   withheld. No resume epoch can reuse a stale readiness proof.
8. Delete through lifecycle and verify container, namespace/helper/peer identity,
   owned workspace/assets and lease bookkeeping disappear; run reconciliation
   again to prove cleanup idempotency. Confirm fixture worker has zero retained
   sandboxes. Remove only named task units/mount/image artifacts approved for the
   fixture; no prune or broad cleanup. Export only public evidence and test results.

Acceptance: both native architectures pass every step and bound. Native-qualified
catalog status and live template registration require a separate reviewed parent
activation change. Failure leaves catalog candidate and launch unavailable. Host
reboot recovery and any additional profile choice remain separate qualification
scope; this local run never manufactures a production Ready state.
