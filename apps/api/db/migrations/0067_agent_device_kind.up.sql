-- S15.2 slice 3 — AN AGENT IS A `devices` ROW, AND IT MUST BE DISTINGUISHABLE FROM A HUMAN'S.
--
-- ⛔ THE REUSE IS THE RULING (rank-3), AND THE GIFTS ARE WHY. Attribution arrives BY CONSTRUCTION — an
-- agent lands in the artifact's /32→device map with no parallel implementation, which is D15 satisfied
-- rather than re-implemented. Revocation's full sweep (peer slot + pool address + telemetry) applies
-- unchanged, so there is no second sweep path that can drift from the first. Those are the two hardest
-- things in this epic and both come free.
--
-- ⚠ AND THE COST IS ONE CONVENTION THAT IS RIGHT FOR HUMANS AND WRONG HERE — the per-user device cap.
-- `CountDevicesForUserCap` counts active + pending, so without this column every agent an admin enrolled
-- would spend that admin's personal laptop allowance. A fleet of gateways charged to one human.
ALTER TABLE devices
    ADD COLUMN kind text NOT NULL DEFAULT 'human'
        CHECK (kind IN ('human', 'agent'));

-- ⛔ THE CAP INDEX IS NARROWED TO HUMANS, NOT LEFT TO A `WHERE` IN ONE QUERY.
--
-- The exemption must hold wherever the cap is counted, and a filter written into a single statement is a
-- guard made the next caller's responsibility — the class this repo has already paid for. A partial index
-- keyed on `kind = 'human'` makes the exempted shape the one the database is built for, so a future count
-- that forgets the predicate is slow and visible rather than silently wrong.
DROP INDEX IF EXISTS devices_org_user_active_idx;
CREATE INDEX devices_org_user_active_human_idx ON devices (org_id, user_id)
    WHERE status = 'active' AND deleted_at IS NULL AND kind = 'human';

-- The agent's device row points back at the node it IS. One device per node.
--
-- ⚠ UNIQUE, so a re-enrolment cannot silently accumulate a second address for the same gateway — pool
-- exhaustion by re-enrolment loop is the org-pool DoS the cap convention was written against, arriving
-- through a door the cap now explicitly does not watch.
CREATE UNIQUE INDEX devices_agent_node_key ON devices (node_id)
    WHERE kind = 'agent' AND deleted_at IS NULL;
