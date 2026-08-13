DROP TABLE org_hub_set;
ALTER TABLE nodes DROP COLUMN hub_priority;
-- HONEST down (S8.6): recreating the single-node UNIQUE index FAILS if any site now holds >1 gateway
-- (a multi-gateway HA site exists) — the down REFUSES loudly rather than silently dropping a bound gateway.
-- Unbind the extra gateways first if you truly mean to roll back the lift.
CREATE UNIQUE INDEX nodes_site_id_uniq ON nodes (site_id) WHERE site_id IS NOT NULL;
