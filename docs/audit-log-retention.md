# Audit-log retention operations

Audit logs default to **Forever** for every existing and new organization. A
missing policy row is the deliberate revision-zero Forever state, so applying
the migration never starts deleting historical evidence.

Organization owners and administrators holding
`audit_log_retention:manage` can use **Settings → Data retention** to keep
Forever or explicitly choose a bounded window from 1 to 3650 days and a cleanup
interval from 5 to 1440 minutes. The read, update, and manual-prune API surfaces
are:

- `GET|PUT /api/v1/organizations/{orgId}/audit-log-retention`
- `POST /api/v1/organizations/{orgId}/audit-log-retention/actions/prune`

Settings updates use revision-based optimistic concurrency and create an
`audit_log_retention.settings_changed` audit event. Manual requests require a
tenant-local idempotency key and create one
`audit_log_retention.prune_requested` event. A repeated key returns its original
durable run and never deletes or audits twice.

## Deletion safety

The database keeps the original append-only posture for ordinary callers:
UPDATE, DELETE, and TRUNCATE remain trigger-blocked. The only exception is a
security-definer function that accepts an exact retention-run ID. In the same
transaction as each deletion batch it:

1. locks and validates that exact run is still running and its lease is live;
2. verifies the run still matches the current persisted bounded policy;
3. derives the organization and cutoff from the immutable run snapshot; and
4. grants transaction-local authorization for at most 1,000 oldest eligible
   rows, then increments the run's deleted-row and batch counters atomically
   with that deletion.

The scheduler and a manual request may run at most 100 batches per claim. A run
that reaches that limit records `more_pending=true`, making the organization
immediately eligible for another bounded continuation. Cutoffs use the audit
row's control-plane `created_at`; callers cannot supply a cutoff, batch size, or
flush-all request. PostgreSQL's own statement clock—not an API host clock—sets
claim start, cutoff, lease, renewal, expiry, and completion times. An expired
claim is reclaimed even when its last batch removed every eligible row or the
policy has since returned to Forever.

Audit rows referenced as Kubernetes connector-handoff CAS provenance are
foreign-key-pinned evidence. Retention deliberately skips them, and they do not
keep `more_pending` true. They remain queryable even after their age window
expires because deleting them would destroy the exact durable handoff proof.

Switching back to Forever prevents new claims and makes the scheduler inactive.
Rows already deleted under an earlier explicit bounded policy cannot be
restored. The UI states that irreversible boundary before saving or running
manual maintenance.

The scheduler creates a run only when an expired, deletable row exists. Fresh
rows and handoff-pinned evidence do not create empty periodic run history.
Automatic terminal run history is capped at the newest 1,000 rows per
organization. Manual runs are retained so their idempotency keys continue to
return the original durable result.
