-- ⛔ ONE DEPLOYMENT-LEVEL AXIS, NOT TWO BOOLEANS THAT MUST AGREE.
--
-- `can_create_orgs` (0073) answered one question. The CP admin needs a second — may this person grant roles
-- in ANY organization — and a parallel column would be the `bandGateways`/`BANDS` shape again: one set of
-- facts with two homes, drifting silently until something built on the stale one ships.
--
-- ⭐ SO `can_create_orgs` IS ABSORBED. `cp_admin` is the axis; creating organizations is IMPLIED by it.
ALTER TABLE users ADD COLUMN cp_admin boolean NOT NULL DEFAULT false;

-- ⚠ NOBODY GAINS AUTHORITY HERE. The set is identical — only the name and the meaning widen.
UPDATE users SET cp_admin = true WHERE can_create_orgs = true;

-- ⛔ THE OLD COLUMN IS **NOT** DROPPED HERE, AND THE MIGRATION LINT IS RIGHT TO INSIST.
--
-- Dropping it in the same release that removes its last reader breaks a ROLLING DEPLOY: old pods are still
-- serving while the migration runs, and they SELECT a column that no longer exists. Expand/migrate/contract
-- — this is the EXPAND. The contract (`ALTER TABLE users DROP COLUMN can_create_orgs`) lands in the next
-- release, once no running binary reads it.
--
-- ⚠ It keeps its NOT NULL DEFAULT false, so inserts that ignore it still work; it is simply inert.
