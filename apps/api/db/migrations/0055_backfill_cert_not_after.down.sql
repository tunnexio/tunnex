-- Irreversible by nature: the pre-backfill state was "NULL for every row predating 0054", and after any agent
-- renews we can no longer tell a backfilled bound from a stamped value. Reverting to NULL wholesale would
-- DESTROY real stamped expiries, which is worse than leaving the bounds in place. A no-op is the honest down.
SELECT 1;
