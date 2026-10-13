# Disconnected timed-member component harness (source only)

Base bdbf6891c2446a48e8d6b82eeaeff1bf39238629. No Docker command, native test, DB operation or cloud action has been run by this source preparation.

Root corrected the actual cached local image to `sha256:00e84e696a0a007f99741b5cb953696ab11084238a5eb3c916bf11d62a40e688`, Linux ARM64. The old 3e83 identifier was a stale compose label and is not usable authority. The harness pins the actual image ID, never that label.

Root must review/build the exact stable source-paired ARM64 test binary separately (no build/pull here), save it regular owner600 in a private700 directory, and independently pin SHA256. Example future compilation, only after separate authorization: from apps/node, `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o <private>/expiry.test ./internal/ipsec`. Full-candidate source identity and toolchain belong in root's binary provenance; the bdbf component alone does not qualify subsequent corrections.

Default invocation makes filesystem checks only; it cannot call Docker:

```
python3 tests/azure-s2s-local/run-disconnected-fqdn-expiry.py \
  --binary <private>/expiry.test --binary-sha256 <reviewed-sha256> \
  --reservation <private>/expiry-run.json
```

Only root-approved `--execute` reserves a unique name before CREATE. The fixed create parameters are: exact image, `--pull=never`, unique UUID name/qualification label, network none, read-only rootfs, cap-drop ALL and only CAP_NET_ADMIN, no-new-privileges, 128MiB executable /tmp tmpfs, 256MiB memory,64 PIDs, shell sleep300. No host bind, volume, Docker socket, restart policy, --rm, privileged/SYS_ADMIN, credentials, image build or image pull. Container inspection must match identity/image/isolation before start. The root-pinned binary is copied by stdin into tmpfs and its in-container SHA256 must match. The harness requires empty actual XFRM state and policy, then creates exactly two XFRM interfaces if_id1001/1002. No SA negotiation or packet fixture is created.

The one exact test is `TestGuardFQDNV2ExpiryNativeReadback`, opt-in env `TUNNEX_IPSEC_FQDN_EXPIRY_LAB=1`, Go test timeout20s/outer25s. Its internal component budget15s reads the two actual interfaces, refuses any existing nft table, tests3s managed member expiry independently from20s connection lease, then owned set turnover. Synthetic reqid/peer fixtures are renderer metadata, NOT observed installed SAs. Exact non-SKIP single PASS is required. Raw native output is never printed; typed result is private600.

Any ambiguous command, timeout, foreign isolation, digest mismatch or failed test preserves the exclusive reservation and container. Existing reservation refuses both default and execute; never replay with the same or newly allocated name as recovery. Root may independently use read-only Docker inspect of the saved exact name to classify unknown outcome. There is no automatic deletion, restart, retry, rollback or native authority assertion. Container sleep exits after300s; it is retained for independent review/cleanup by the sole authorized writer.

Offline tests: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/azure-s2s-local -p 'test_disconnected_fqdn_expiry_harness.py'` —10PASS. These mocks establish default-no-Docker, private input/hash refusal, durable create-timeout/no replay, foreign-image-before-start refusal, and symlink-parent refusal. They do not establish platform capability availability or native PASS.

Pre-start follow-up: the exact returned container ID is written to a new private `.created.json` before inspect or start. Every private record fsyncs both file and parent directory; durability failure leaves the original reservation and refuses replay. Inspect verifies exact memory256MiB/PIDs64/tmpfs/security option, fixed entrypoint/Cmd and qualification label in addition to original isolation checks. Offline negative fixtures perturb each setting and prove no START; a valid fixture simulates START timeout and retains identity.

Final component evidence: `.component.json` is exclusive private600 and durable before interpreting exit/PASS. It preserves bounded original stdout/stderr bytes as base64, per-stream digests, actual return code, and timeout flag/partial output. No binary input or prior Docker command data is recorded. Successful redacted output includes the component receipt filename and SHA256. Nonzero, timeout, SKIP or malformed PASS retains all bytes/CID/reservation without replay. Internal15s/test20s/outer25s are unchanged. Offline tests cover actual failed/timeout partial output preservation and receipt hash/SKIP refusal.

Canonical capability correction: Docker CREATE accepts `--cap-add NET_ADMIN` but inspected HostConfig.CapAdd must equal exactly `["CAP_NET_ADMIN"]`. The legacy spelling in readback and any extra capability refuse; all other isolation checks remain exact. The already-created failed run is untouched. This change does not authorize CREATE/START replay.

Native absence correction: the component-only census now runs unfiltered `/sbin/ip xfrm state list` and `/sbin/ip xfrm policy list` inside the disconnected container. Each command must exit zero and return exactly zero stdout bytes. Empty JSON output is never converted into an invented array; blank lines, JSON arrays, any object text or command failure refuse. This is full plain-listing absence observation only in the component namespace, not proof of owned SAs or production cleanup. Original classified container/receipts are untouched; this source change does not permit replay.

Executable fixture mount correction: CREATE explicitly requests `/tmp:rw,nosuid,nodev,exec,size=128m`, and HostConfig readback must match that exact single mount. Execution is confined to the pinned disconnected component binary; all other isolation remains unchanged. Offline fixtures refuse implicit/default noexec, explicit noexec, and additional tmpfs mounts before START. The prior exit126 permission-denied receipt remains a pre-Go-test failure, with no native PASS claim; neither previous reservation/container is retried or changed.
