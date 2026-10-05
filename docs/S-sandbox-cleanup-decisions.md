# Sandbox reconciliation and cleanup decisions

Paper before implementation; public creation remains closed.

First reconciler slice handles stop/delete/TTL, including recovery after a crash. Serialize each sandbox through a PostgreSQL session advisory lease; never keep a database transaction open across provider/network calls. Persist stopping/deleting intent before side effects, then compare exact desired generation when completing. A stale worker cannot acknowledge a newer intent. Expiry becomes terminal deletion intent.

Stop withdraws network access, confirms provider stopped, and retains peer identity/credential hash for future restart. Delete withdraws credentials and health-blocks the peer before external calls, retaining its active allocation until gateway removal is confirmed. Clear live device telemetry. Provider deletion and positive network removal evidence precede deliberate peer revocation, deleted tombstone and quota/address release. Inspection found the allocator excludes revoked rows even when their address remains: health-blocking preserves the reservation during cleanup without changing ordinary allocation semantics. No missing-provider/socket error may count as successful cleanup unless it is the provider's explicit missing result.

The network coordinator is an internal trusted interface whose positive receipt must match sandbox/peer/generation. There is no production implementation or fake default. Cleanup may complete without a network receipt only when no peer was ever bound. Lease holder rechecks durable state and uses provider ownership checks; retries repeat idempotent cleanup after partial failure. Readiness remains a separate gate: generation-matched current-policy acknowledgements, qualified network isolation and private SSH probe, not provider Running.

Local Docker Desktop is not the rootless Podman Ubuntu host used by the manual pilot, and no local Podman binary exists. Host networking qualification is therefore still pending. Do not touch pilot or unrelated services to compensate. Internal synthetic tests qualify control-state behavior only.
