# F02 migration collision proof

Date: 2026-08-15 UTC

Target: `tunnex-cp` (`ubuntu@54.66.253.232`)

Source content tip: `bd8efbcaccdba8b299e91be127fa2d5380f223a1`

## Rollback point

- Fresh backup: `/home/ubuntu/tunnex/backups/pre-ai-agent-f01-f04-20260815T045504Z`
- Backup manifest verification: PASS.
- `SHA256SUMS` verification: PASS.
- PostgreSQL dump size: 377143 bytes.
- Pre-test live schema: `87|dirty=false`.

The backup also contains the active compose/release configuration, container and
image inventory, keyed master-key fingerprint manifest, and archives of both
node-state volumes and the Tunnex secrets volume. No secret value was printed or
copied into this artifact.

## Collision-safe sequence

Cluster migrations retain versions 0079 through 0087. The AI-agent migrations
were renumbered without changing their SQL behavior:

- F01 agent profiles: 0088
- F02 multi-agent gateway cardinality: 0089
- F03 bootstrap credentials: 0090
- F04 runtime state: 0091
- F02 organization quota: 0092
- F04 organization opt-in: 0093

The 18 cluster migration SQL files were verified byte-for-byte against the
measured cluster-scope source.

## Disposable clone result

The fresh dump was restored into disposable database
`tnx_ai_agent_20260815045710`. The live `tunnex` database was not used as a
migration target.

1. Clone started at `87|dirty=false`; agent tables were absent.
2. Embedded current-head migration binary applied through
   `93|dirty=false`.
3. `agent_profiles`, `agent_bootstrap_tokens`, and
   `agent_runtime_state` were present.
4. Six one-step rollbacks completed cleanly: 93 → 92 → 91 → 90 → 89 → 88 → 87.
5. Agent tables were absent again at `87|dirty=false`.
6. Re-applying completed at `93|dirty=false`; organization and device counts
   were preserved.

Migration binary SHA-256:
`c8df53c098a42a4af02058da225032c9a418c5bc44b51c7d5206eae2dbc382eb`.

Remote redacted proof SHA-256:
`ed7c80627cb24c04c4f26b1cadc6420718a417ccca7d2e1732b6e53d960868a9`.

## Non-skipped PostgreSQL tests

A separate disposable admin database and throwaway child databases were used.
The live database was not supplied as `TUNNEX_TEST_DATABASE_URL`.

- `TestMultiAgentPerGatewayRollback`: PASS.
- `TestAgentRuntimeOptInMigrationPostgres`: PASS.
- `TestK8sClusterScopeMigrationUpDownUp`: PASS.

Remote redacted test evidence SHA-256:
`d7c656133c201d2bbe534619870593ec204ebd9f634854d7a04b39559a408f60`.

Local `go test ./db -count=1` and `git diff --check` also passed.

## Live-state preservation

Before and after the disposable proof, live counts remained:

- organizations: 2
- devices: 40
- cluster-scope grants: 1
- cluster-scope memberships: 2
- schema: 87

No live service was restarted, no live schema was migrated, and no image was
loaded or activated.
