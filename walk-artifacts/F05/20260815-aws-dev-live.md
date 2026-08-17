# F05 AWS DEV acceptance — 2026-08-15

## Scope and provenance

- Branch: `story/F05-credential-rotation`
- Development head entering the walk: `9bf5685`
- Migration repair: `9462090`
- Hub warm-candidate repair and accepted live head: `b890698`
- DEV control plane: `54.66.253.232`; disposable runtime: `52.64.126.224`
- No plaintext bearer, token hash, WireGuard private key, password, or session cookie is present in this artifact.

The pre-mutation rollback point is
`/home/ubuntu/f05-rollback-9bf5685-20260815T1128Z`. Its custom PostgreSQL
dump and manifest verified before deployment. The prior API, web, and node
image IDs were recorded there. Migration began at schema `93|false`.

## Deployment and migration

- Exact `9462090` API migrated PostgreSQL `93 -> 94`; API and web became
  healthy with zero restarts and schema `94|false`.
- The first live migration exposed a real inactive-agent backfill defect. The
  migration now disables only the existing agent-ownership trigger around the
  legacy metadata backfill and re-enables it in the same transaction.
- Exact `b890698` API image ID:
  `sha256:e80fee795a5e5012a211f626a10c2eedad10534c602012f069a272a378a9d972`.
- Exact signed `b890698` runtime SHA-256:
  `f634878e7a1d6be117418e99661a942f7cad252a7ebc0e4768a2fd55d9358ff1`.
  The signed manifest and all release checksums verified before installation.
- DEV advertised `gateway.tunnex.app:8443` but the Compose environment exposed
  only `18443`. The scoped walk override published both TCP ports, preserving
  the existing binding and all UDP/WireGuard listeners. External gateway
  reporting then resumed. Production deployment must keep the advertised
  control endpoint and `HOST_API_MTLS_PORT` aligned.

## One combined rotation and lifecycle walk

1. A real reporter handshake existed before rotation. The disposable runtime
   service was active/enabled, `NRestarts=0`, and its three root-owned durable
   files were mode `0600`.
2. Owner rotation requested bearer and WireGuard successors. The runtime
   generated both successors locally. The CP received only the bearer hash and
   WireGuard public key.
3. Bearer revision 2 promoted without a process or tunnel restart. The old
   bearer returned uniform `401`; the promoted bearer returned authorized
   no-change `204`. Restart during the lost-response window recovered the
   protected local candidate and did not churn the tunnel.
4. The first WG stage found that hub peer widening replaced the peer list after
   the candidate was appended. `b890698` restores the warm candidate after
   widening. The gateway then acknowledged the empty-AllowedIPs peer, reported
   its real nonzero handshake, and the CP atomically committed WG revision 2.
   The old public key retired only after that report.
5. Terminal runtime state was bearer revision 2 and WG revision 2, with one
   nonzero handshake, `NRestarts=0`, changed bearer/key, and no `.candidate` or
   `.previous` secret files.
6. A later rotation reached a real staged WG candidate. Suspend canceled the
   pending WG work, preserved the promoted current bearer and WG revision 2,
   removed the interface, and exited cleanly inactive with `NRestarts=0`.
7. Resume with the preserved current credentials restored revision 1 config and
   a real handshake. A final live candidate stage followed by revoke invalidated
   the current bearer, cleared pending WG state, returned current-bearer `401`,
   removed the interface, and left systemd cleanly inactive with
   `Result=success`, `NRestarts=0`.

## Released route and authorization

- The released owner `/agents` route rendered the credential and WireGuard
  revision projection with no bearer/hash/private-key-shaped text.
- Clicking **Rotate credential** returned `200`, and the component rendered the
  server-refetched requested state and deadline.
- A fresh owner browser session rendered the same requested state and deadline,
  proving persistence after refetch rather than optimistic UI state.
- The released member `/agents` route made zero credential-rotation requests;
  its DOM contained no rotation panel, action, revision, or deadline.
- Direct member access to the rotation status endpoint returned uniform `403`
  with only the normal error envelope and no telemetry.
- Both disposable live-walk agents were revoked after their respective proofs.

## Focused exact gates

```text
GOCACHE=/private/tmp/tunnex-f05-go-cache go test ./internal/nodes \
  -run 'TestWarmWireGuardCandidateNeverDuplicatesAllowedIPs|TestHubWideningRetainsWarmWireGuardCandidate' \
  -count=1
PASS

TUNNEX_TEST_DATABASE_URL=<disposable-postgres> \
  GOCACHE=/private/tmp/tunnex-f05-go-cache go test ./db \
  -run '^TestAgentCredentialRotationMigrationPostgres$' -count=1 -v
PASS (pristine down, reapply, bounded history, refusal, hash/request preservation)
```

The development commits also carry the focused API authorization/promotion,
runtime executable rotation/rollback/restart, migration contract, generated
client, and released-route component gates recorded in their commit evidence.

## Result

F05 is accepted on AWS DEV. Runtime bearer rotation, WireGuard stage/handshake
cutover, rollback preservation, suspend/resume, revoke/offboard, released owner
refetch, and member information hiding all passed without changing unrelated
gateway or WireGuard resources.
