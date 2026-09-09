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
