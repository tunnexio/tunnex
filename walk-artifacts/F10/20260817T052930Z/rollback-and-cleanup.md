# Rollback and cleanup

- Exact Linux test binary built from the story content ran inside the healthy
  DEV API container against uniquely named disposable PostgreSQL databases.
- `TestAgentJITAccessMigrationPostgres` passed: empty 98 -> 97 preserved the
  pre-F10 expiring rule, 98 reapplied cleanly, and populated rollback refused
  while preserving request, append-only event and pre-existing rule rows.
- The test dropped its disposable databases. The shared DEV database never
  migrated down and remained version 98, dirty false.
- Opt-in was restored Off with zero pending/approved requests.
- Both disposable agents were canonically revoked then removed. The disposable
  group, membership and destination were deleted. Append-only terminal request
  history remains intentionally as the audited workflow record; there is no
  live request or rule.
- On the agent VM the runtime service is inactive, interface absent and all five
  managed runtime paths are absent. `/dev/net/tun` and `releaseverify` remain.
- Bootstrap response, installer, password handoff and test-binary scratch were
  erased locally and remotely. No reusable secret is present in this packet.
- Final shared services were healthy, severe-log count was zero, and the F10
  organization opt-in was false.
