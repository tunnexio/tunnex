# Agent rotation crash recovery correction

Preserve the prepared candidate when restart occurs after writing .previous but before replacing the active credential. This fulfills existing restart recovery semantics: never generate a different candidate for the same server revision. Cleanup requires a successful successor poll, not a successful poll using the previous credential. Unknown HTTP failures retain recovery material. Existing401 rollback remains unchanged.

Live reproduction: test runtime paused at .previous atomic handoff, killed and restarted; old credential remained active, candidate was deleted/recreated, CP stayed candidate at revision2 and reporting became stale. Fix runtime Poll cleanup guard; regression first, then repeat live walk. If needed, use test-identity suspend/resume to cancel the failed candidate, never manual server hash edits.

## Cancelled rotation retry (approved 2026-09-13)

User disposition: **Approved: use next unused revision**. A revoked candidate remains terminal history and is never revived. Under the existing device transaction lock, allocate `max(retained revision) + 1`; an existing candidate retains its revision for idempotent retries. Request responses, runtime polls, preparation and operator status must agree. Preparation revalidates the authenticated current revision after locking; arbitrary jumps and stale identities remain refused. Promotion accepts the exact prepared successor even when cancelled history creates gaps. WireGuard revisions retain their independent existing sequence. No schema or public API change is required.

Regression proof covers cancellation and expiry, retry/promotion across a gap, immutable revoked history, replay, stale identity and arbitrary revision refusal. Repeat the lab crash-handoff walk after API deployment; success requires successor auth, predecessor rejection and runtime recovery. Direct revision reuse, deleting history and reviving revoked credentials are rejected.
