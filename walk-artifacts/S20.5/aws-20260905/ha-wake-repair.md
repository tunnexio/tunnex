# HA wake/authority repair — 2026-09-06

Status: source correction tested; AWS retest pending. This is the targeted
acceptance path, not a restart of the historical eleven-leg checklist.

Decision: [acknowledged-base reuse and pending delivery cursor](../../../..//docs/S20.5-ha-acknowledged-base-reuse-decisions.md).

## Reproduction and bounded correction

The exact pre-fix API source `bb9ef15` reproduces renewal starvation in both
editions with a deterministic real-PostgreSQL runtime/authority/lease test.
Three cursor-only wake changes increase authority rows from 6 to 9, 12 and 15,
while the serving expiry never advances. The silent standby had already ACKed
the initial arm and ordinary base. A paired MTU/content-change control correctly
keeps renewal blocked until the final member's exact acknowledgement.

The fix reuses only the latest acknowledged ordinary delivery when canonical
content, classifications and generations are unchanged. It preserves its
immutable receipt tuple. Pending delivery responses may echo the original
earlier cursor only for exact principal/full-hash matches; future versions and
changed bytes still refuse. Scheduler capture now precedes compilation.
There is no node production, protocol, migration, lease-duration or grant change.

## Targeted verification

- New regression is RED before the repair and GREEN after it, both editions.
- Directly affected API node tests: 21 top-level tests plus subtests in each
  edition, PASS (open 14.901s, enterprise 14.648s). Includes seven independent
  store cases: immutable accepted replay, hash/classification/generation changes,
  unACKed cursor change, no historical receipt reuse, and strict transition replay.
- Existing bootstrap/expiry, ACK locking/read failures, canonical and principal
  checks remain passing. Test databases are independently owned and cleaned by
  their fixture; final task database schema is 136, clean.
- HTTP exact pending tuple, receipt, current cursor resumption and negative
  identity/hash/future/zero cases PASS in both editions.
- Node cursor-pin tests PASS: strict tuple checking remains, an earlier cursor
  conservatively retains an unrelated released fence, and the current cursor
  restores its prior projection. No inference of unfence or receipt relabelling.
- Canonical `make build-editions` PASS, both API editions.
- Independent bounded source review found no concrete P1/P2 in this production
  diff. This does not substitute for final story review or live acceptance.

Affected node API logs SHA256:

- open: `418d5dd92e43fd6e9a4c3d3e84c65d4cbae0cc666efe00a1fb1dd0c952707123`
- enterprise: `56babf3fb3969176ee76f5c61305a04df275cf496f0e9c8b291efb0b63b4ef44`

Logs remain task-local; no credentials, kubeconfig, certificates or private keys
are included. Earlier exact `48f96b0` CI is fully green but is not final-HA CI.

## Live pre-retest observation

Read-only account verification returned AWS account `735391218823`, principal
`aws-cli`, region `ap-south-1`; main remained `0f3d9b0`. All three existing
gateways were Ready on node digest `147a81bd…`; the old API was healthy on
`0c33825f…`. Fresh laptop IP/DNS probes initially timed out, then both recovered
without intervention. This is intermittent traffic, not a healthy baseline claim.
No machines, charts, client settings or cloud resources were changed for setup.

Next: publish/deploy only the reviewed API candidate, then baseline and bounded
standby/owner fault/recovery probes with original identities preserved.
