-- S7.4b: the desync-onset timestamp for the differentiated health surface (X-4).
-- CONTROL-PLANE-OWNED: stamped by the CP at report-ingest (CP clock, X-2) when it first
-- observes term-3 (pushed policy hash != agent-applied hash), cleared on positive
-- reconvergence. NOT in the agent-fed `capabilities` JSONB (which the CP rebuilds from the
-- typed report each cycle → would clobber + is agent-reachable in principle); a dedicated
-- column is CP-write-only BY CONSTRUCTION — no agent payload path touches it.
-- NULL = not currently desynced (or reconverged).
ALTER TABLE nodes ADD COLUMN policy_desync_since timestamptz;
