-- Down-migration [7] discipline (S7.5.4): drop the DEPENDENT column/index BEFORE the tables it
-- references, so a POPULATED schema (a registered site + subnet + bound node) rolls back cleanly
-- instead of aborting on a live FK. Tested up->down->up with populated rows (sites_migration_test.go).

-- nodes.site_id references sites — drop it (and its data) first so DROP TABLE sites has no referrers.
DROP INDEX IF EXISTS nodes_site_id_uniq;
ALTER TABLE nodes DROP COLUMN IF EXISTS site_id;

-- site_subnets references sites — drop it before sites (its rows go with it; no group equivalent to
-- preserve in the pre-S8.1 model, exactly like the S7.5.4 [7] per-user purge).
DROP TABLE IF EXISTS site_subnets;
DROP TABLE IF EXISTS sites;
