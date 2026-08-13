-- Restoring the unconditional constraint FAILS if any org holds a revoked and an active node of the same name —
-- which is the state this migration exists to permit. That failure is correct and loud: reverting would have to
-- destroy or rename real rows, and a migration must not do that silently.
DROP INDEX nodes_org_id_name_active_key;
ALTER TABLE nodes ADD CONSTRAINT nodes_org_id_name_key UNIQUE (org_id, name);
