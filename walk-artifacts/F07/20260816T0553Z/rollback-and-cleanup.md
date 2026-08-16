# F07 rollback and scoped cleanup

- An isolated PostgreSQL 16 container on the DEV CP ran the exact Linux test binary from commit `8779212`.
- `TestAgentAccessEventAttributionMigrationPostgres` passed in `7.66s`:
  - empty schema 96 -> 95 down succeeded and removed the F07 attribution column
  - 95 -> 96 up-again succeeded
  - down with an attributed event refused and preserved the event, `policy_hash=abcdef123456` and `src_kind=agent`
- The disposable PostgreSQL container and copied test binary were removed after the proof.
- Supported APIs deleted the F07 rule/resource, revoked and soft-removed the F07 agent, then revoked and deleted the F07 reporter gateway; all returned HTTP 204.
- The runtime offboarded cleanly: service inactive, interface absent, `Result=success`, `ExecMainStatus=0`, `NRestarts=0`.
- The five managed runtime paths and unit were removed from the DEV agent VM; `/dev/net/tun`, `releaseverify` and the base OS were preserved.
- The reporter container/volume, scoped HTTP process, loopback address and task scratch were removed. Final database counts for the F07 device, node, rule and resource were all zero.
- DEV schema remained `96`, `dirty=false`; API, web, node, PostgreSQL, Redis and edge remained healthy.
- The operator removed temporary AWS SG rule `sgr-09b96f7f95123e329`; a fresh console read showed nine inbound rules and no UDP/51977 or `F07 disposable reporter` entry.
