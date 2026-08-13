-- S7.5.1 fold (review #1/#6): a per-org, SWEEP-PROOF flow-event seq counter.
--
-- The ingest previously derived seq from MAX(seq) of access_events, which (a) collided under
-- concurrent same-org ingest (READ COMMITTED, no lock) -> silent audit loss, and (b) would
-- REWIND to 1 once retention swept an org's rows -> duplicate seq across JSONL segments,
-- breaking the per-org monotonic tamper-evidence.
--
-- flow_seq lives on organizations (NOT in the swept access_events table), so it survives the
-- retention sweep, and the ingest reserves its range with `UPDATE ... SET flow_seq = flow_seq
-- + n RETURNING flow_seq`, whose row lock serializes concurrent same-org ingest. Seeded from
-- the current per-org high-water so existing streams continue monotonically (no reuse).
ALTER TABLE organizations ADD COLUMN flow_seq bigint NOT NULL DEFAULT 0;

UPDATE organizations o
SET flow_seq = COALESCE((SELECT MAX(e.seq) FROM access_events e WHERE e.org_id = o.id), 0);
