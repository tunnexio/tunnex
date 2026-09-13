# Agent rotation crash recovery correction

Preserve the prepared candidate when restart occurs after writing .previous but before replacing the active credential. This fulfills existing restart recovery semantics: never generate a different candidate for the same server revision. Cleanup requires a successful successor poll, not a successful poll using the previous credential. Unknown HTTP failures retain recovery material. Existing401 rollback remains unchanged.

Live reproduction: test runtime paused at .previous atomic handoff, killed and restarted; old credential remained active, candidate was deleted/recreated, CP stayed candidate at revision2 and reporting became stale. Fix runtime Poll cleanup guard; regression first, then repeat live walk. If needed, use test-identity suspend/resume to cancel the failed candidate, never manual server hash edits.
