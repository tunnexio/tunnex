# CP recovery latency: pool diagnosis

User requested fixing the remaining CP latency blocker. Preserve auth and
forwarding deadlines. Start with private, parameter-free pool metrics: acquired,
idle, maximum connections; acquisition count/duration, empty-pool waits and
cancellations. Scraping these must not query the database or expose SQL/identities.

Current pool factory retains pgx defaults. On the 2-core walk host that defaults
to four connections; scheduler leadership holds one for its lifetime. Low CPU
and ample RAM do not rule out client-side pool starvation. This is a hypothesis
until acquisition telemetry and a controlled same-build comparison support it.
Do not infer DB lock contention from API timeout alone. Keep explicit customer
pool configuration authoritative; never disable required TLS/channel binding.

Measured baseline: max4, repeatedly acquired4/idle0. Cumulative successful
empty-pool wait grew from8.84s to118.18s during roughly50s of a bounded three-round,
three-concurrent-read probe plus ordinary background work. `/nodes` took6.6–10.1s;
`/devices`4.7–8.3s. This proves client-side acquisition delay, not a DB lock cycle.

Bounded correction: default runtime pool floor16 (retain pgx's larger CPU-derived
default and any explicit `pool_max_conns`). This is a per-replica capacity ceiling,
not 16 eagerly opened connections or a universal sizing guarantee. Operators must
budget across replicas and their database capacity. Keep pgx URI/keyword settings
as the override rather than inventing another tuning format. Direct migration/
preflight connections must consume those pool settings locally, never send them
as PostgreSQL GUCs. Keep channel-binding enforcement on all connection paths.
Compare same new binary with explicit4 versus default16; then retest recovery.

## Live result (11:33 UTC)

The explicit4 override was refused at startup by the existing common PostgreSQL
URL preflight whitelist. Removed that override immediately. Parser preservation
tests are NOT end-to-end support for a customer pool URL option; the common URL
contract remains narrower. No same-binary A/B claim is made.

Default16 started successfully. Same nine-read probe passed: `/auth/me`
1.53–1.67s, devices3.20–7.40s, nodes4.55–8.59s. Successful pool-wait growth
settled at23.66s and remained unchanged for40s with idle connections available;
one canceled acquisition was recorded. This reduces measured acquisition
pressure, but does not establish that all request latency is fixed.

With candidate API image `f920645edb1a`, node SHA
`f7b1c01640e7ca9695c9dce10215794858ba2dd499b4715d9e9977b6d7303b1e`
and installed client/helper, generation25 was created. Candidate PUT returned500
after6.19s; cleanup DELETE returned500 after6.45s. The native walk FAILED BEFORE
TURN restart. Driver cleanup confirmed helper Down and revoked the temporary
credential. Next diagnosis is the bounded mailbox transaction itself, not another
pool-size increase or a relaxed forwarding/authorization deadline.

Focused dbconn/dbcheck/metrics tests pass in both editions; race tests, vet and
both API builds pass. Enterprise connectivity/nodes package tests pass without
the isolated-DB integration variable (not live DB coverage). Two bounded reviews
of pool configuration and private metrics returned no actionable findings.

## Next bounded reduction

Topology locks currently consume three sequential round trips while retaining
eligibility locks. Pipeline those same generated statements in the same order
(hub set, ordered nodes, ordered sites), in the same transaction. Drain/close
the batch before reading the wall clock or deriving the active gateway. A small
handwritten composition helper beside generated sqlc queries can reference their
constants without copying SQL or editing generated files. Preserve owner checks
before these locks, error propagation, rollback and the five-second transaction
deadline. This is a latency reduction, not evidence that every hosted workload
fits the deadline. Re-prove the actual recovery before claiming the blocker fixed.
