# Postrestart FQDN partial snapshot

Exact070 completed normal GET-only licensed generation observation and full baseline preservation, but aggregate generation_accepted:false. App activegeneration297/fresh81.10 and real NXDOMAIN passed. Alias binding validation passed, but latest stored generation was failed/timeout, with no active answers or freshness. API service.go366 projects stored latest failure and performs no new DNS query.

This snapshot alone cannot identify mailbox/worker/transport cause or distinguish transient failure. No acceptance rule was relaxed and no live query/retry was run by the archive agent. Earlier successful normal generations remain historical; current full DNS/generation readiness is not inferred from gateway payload recovery.
