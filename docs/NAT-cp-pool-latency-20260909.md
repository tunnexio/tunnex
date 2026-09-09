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
