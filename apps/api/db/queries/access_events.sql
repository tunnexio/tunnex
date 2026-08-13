-- name: InsertAccessEvent :exec
-- The id is app-generated (uuid v7) so the SAME id identifies the row in BOTH the PG
-- hot-window and the JSONL source-of-truth stream. seq comes from BumpOrgFlowSeq (a per-org
-- locked counter), so it is unique by construction — this is a PLAIN insert (NO
-- `ON CONFLICT DO NOTHING`): the (org_id, seq) unique index is a FAIL-LOUD backstop, so an
-- impossible collision errors the batch (agent -> next-report gap) rather than SILENTLY
-- dropping audit rows (review #1). No replay path re-inserts: a failed batch rolls the tx
-- (and the counter bump) back, so a retry re-reserves a fresh range.
INSERT INTO access_events (
    id, org_id, seq, node_id, occurred_at, decision, rule_id,
    src_device_id, src_user_id, src_ip, dst_ip, dst_resource_id, dst_group_id,
    protocol, dst_port, deny_count, window_end, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13,
    $14, $15, $16, $17, $18
);

-- name: InsertAccessEventBatch :batchexec
-- The hot ingest path (review fold-2 #6): pipeline a whole batch's inserts in ONE round trip
-- instead of N sequential Execs, so the process-global ingest mutex is held for far less time.
-- Same plain insert as InsertAccessEvent (seq is unique via the counter; the unique index is
-- the fail-LOUD backstop).
INSERT INTO access_events (
    id, org_id, seq, node_id, occurred_at, decision, rule_id,
    src_device_id, src_user_id, src_ip, dst_ip, dst_resource_id, dst_group_id,
    protocol, dst_port, deny_count, window_end, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13,
    $14, $15, $16, $17, $18
);

-- name: BumpOrgFlowSeq :one
-- Atomically reserve `n` seq values for an org and return the NEW high-water. The UPDATE
-- takes a ROW LOCK on the org, serializing concurrent same-org ingest so two batches can
-- never derive colliding seq (review #1). flow_seq lives on organizations and is NEVER swept,
-- so seq is monotonic + sweep-proof (review #6). The batch's seqs are (returned-n+1)..returned.
UPDATE organizations SET flow_seq = flow_seq + sqlc.arg(n)::bigint
WHERE id = sqlc.arg(org_id) AND deleted_at IS NULL
RETURNING flow_seq;

-- name: DistinctAccessEventOrgs :many
-- lint:cross-org — retention housekeeping enumerates the orgs that actually HOLD events so the
-- per-org row-cap sweep bounds every such org's hot-window disk use. This MUST include
-- SOFT-DELETED orgs: a deleted org's event flood is exactly what the disk-guard cap must bound
-- (fold-3 #3 reverted the fold-2 organizations-table enumeration, which excluded deleted orgs).
-- PERF LEDGER: this is a DISTINCT scan of access_events every RetentionSweepInterval; if
-- access_events scale makes the 10-min scan measurable, add a supporting index / cheaper
-- enumeration (trigger, not a silent now-do-it).
SELECT DISTINCT org_id FROM access_events;

-- name: ListAccessEvents :many
-- Keyset page, newest-first, scoped by org. Expanded (created_at, id) < (cursor) predicate
-- (row-value form confuses sqlc's type inference for the id cursor). First page passes a
-- far-future created_at + a max uuid so the whole feed is < the cursor. Uses
-- access_events_org_created_id_idx.
SELECT * FROM access_events
WHERE org_id = $1
  AND (created_at < sqlc.arg(before_created_at)
       OR (created_at = sqlc.arg(before_created_at) AND id < sqlc.arg(before_id)))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListAccessDenies :many
-- The security-focused feed: deny + deny_aggregate + terminated only, same keyset shape.
SELECT * FROM access_events
WHERE org_id = $1
  AND decision <> 'allow'
  AND (created_at < sqlc.arg(before_created_at)
       OR (created_at = sqlc.arg(before_created_at) AND id < sqlc.arg(before_id)))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: SweepAccessEventsByAge :execrows
-- lint:cross-org — retention housekeeping runs across ALL orgs by INGEST age (created_at,
-- not the agent-clock occurred_at, so agent skew can't extend retention). The JSONL stream
-- keeps the full record; PG is a bounded cache, so this delete is lossless for export.
DELETE FROM access_events WHERE created_at < sqlc.arg(older_than);

-- name: SweepAccessEventsOverCap :execrows
-- Per-org row cap: keep the newest keep_newest rows for the org, delete the rest. Protects
-- the disk when one org is noisy without touching quiet orgs.
DELETE FROM access_events AS target
WHERE target.org_id = sqlc.arg(org_id)
  AND target.id NOT IN (
    SELECT ae.id FROM access_events ae
    WHERE ae.org_id = sqlc.arg(org_id)
    ORDER BY ae.created_at DESC, ae.id DESC
    LIMIT sqlc.arg(keep_newest)
  );
