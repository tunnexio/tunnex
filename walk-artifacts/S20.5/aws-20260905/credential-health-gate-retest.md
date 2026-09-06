# Credential and health-report correction — 2026-09-06

Product source: `48f96b0bd5b350a60d889b15c27d83ef02c158c8`.
This is an API/test correction, **not a new live deployment or completed walk**.
The CP still runs the API lock candidate; Kubernetes nodes/managers still run
the transit candidate documented in `transit-snat-retest.md`.

## Correction and review

The runtime bearer transition now locks the exact device before re-reading
credentials in a fresh READ COMMITTED statement. Candidate promotion is two
ordered statements in one transaction: exact predecessor demotion, then exact
successor promotion. Expiry is rechecked after lock waits; refusal rolls back.
Current/candidate uniqueness and immutable audit migrations are unchanged.
Preparation and rotation requests use the same device serialization boundary.

Independent review identified an adjacent request-versus-gateway-report lock
cycle. The dispositioned fix tries the exact existing WireGuard row NOWAIT
before any credential write; SQLSTATE 55P03 returns the existing conflict.
The real stage/handshake-commit regression proves prompt refusal with unchanged
credentials, then successful gateway commit and ordinary operator retry.
No gateway handshake authority or ReportStatus product code was rewritten.

Two failing fixture families now own fresh, fully migrated test databases,
with exact-name teardown and visible cleanup errors. No historical fixture,
shared database, production audit trigger or live CP data was deleted.
Final focused-run census found zero remaining databases in the helper's exact
generated namespace; shared task schema remained 136 and clean.

The agent report handler now preserves the two existing unavailability booleans.
All four true/false combinations, recovery, omitted-field compatibility and
spoofed body identity are tested through handler/service/database readback.
Certificate identity selects the node. This does not make an older agent's
missing fields independent evidence of watcher health.

Self-review plus independent folded-code review found no remaining P1/P2 for
this bounded slice. This is not the required whole-story multi-finder review.

## Local proof

- Full agentruntime and fixture-helper packages: PASS in both editions;
  runtime 5.919s open, 6.436s enterprise in the final focused run.
- Enterprise bootstrap fixture tests: all four PASS, 3.650s. Open has no such
  tests under the existing enterprise build tag; no invented open coverage.
- Affected runtime/access and health-report HTTP tests: PASS in both editions,
  3.266s / 3.234s.
- SQL contract tests: PASS. Generated sqlc was regenerated, not hand-edited.
- Exact committed-source `make generate-check`: PASS, no drift.
- Exact committed-source `make build-editions`: PASS, both editions.
- Exact committed-source `make migrate`: PASS at 02:55:19.071286803 UTC,
  schema 136, not dirty.
- Exact committed-source full `make test-editions`: PASS, both complete
  editions, exit 0 observed at 03:02:15 UTC. No retry. Runtime packages passed
  in 6.161s / 6.020s, devices 4.880s / 10.133s, HTTP 6.175s / 6.763s,
  database 56.640s / 44.030s and nodes 36.521s / 38.051s (open / enterprise).

All database work selects explicit Compose project/network/stores
`tunnex-s205-aws-20260905a`; no default project was used. Full gates read clean
detached source, while generation ran separately in the clean story lane.
The user's root checkout stayed on its original branch and was unchanged.

Focused log SHA256:
`f66505b64a70e5c71ef37e58ad4471c2ab9a53f6f7929218d187554495387355`.
Both-edition build log SHA256:
`58fafadc137569bdc3e16f691711264ee639416fc302630f28688b3f8ac1441b`.
Complete logs remain task-local; they are not credentials or walk acceptance.

## Native CI without a premature PR

Manual [CI run 34007847193](https://github.com/tunnexio/tunnex/actions/runs/34007847193)
is verified against the exact product SHA above. It was dispatched on the
story branch while local full tests continued. Native macOS, native Windows
and the Linux CLI job have passed; the composite gate is still IN PROGRESS,
so required CI is not yet green. The workflow's non-PR classifier runs all gate families. Image
publication/release/site-sync require push/main-or-tag conditions and are not
authorized or activated by this branch workflow dispatch. No PR was opened.

HA same-content version churn and startup exact-base mismatch remain separate
open findings. No fencing barrier, lease duration, private DNS/client settings,
or named recovery deferral was changed by this correction.
