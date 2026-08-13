-- 0037 hub set — HA transit-hub election (S8.6 Slice 2).
--
-- THE SINGLE-NODE LIFT: S8.1's partial unique index nodes_site_id_uniq (one gateway per site) is DROPPED
-- so a site can hold MULTIPLE gateways (the AWS site's primary + standby, the D6 walk). The constraint was
-- built as a PARTIAL UNIQUE INDEX precisely so this moment is an index change, not a schema redesign
-- (S8.1's reserved seam firing as designed). The invariant that replaces it: NONE at the DB tier beyond the
-- org/site FK sanity already present — the ELECTION owns hub-set semantics (the DB stores members, the CP
-- orders them). A site with N gateways is legal; which is the transit hub is a computed+persisted election,
-- not a uniqueness constraint.
DROP INDEX nodes_site_id_uniq;

-- hub_priority — the ADMIN PIN (D1): a nullable rank on a gateway node. Lower sorts FIRST (more preferred);
-- NULL = unpinned. The election orders hub_priority (pinned, ascending) > health > id — operators outrank
-- the election's magic; the election only breaks ties among the unpinned.
ALTER TABLE nodes ADD COLUMN hub_priority int;

-- org_hub_set — the PERSISTED transit-hub election (D1/D5), ORG-LEVEL (one transit hub for the org's whole
-- site mesh — the verified model; NOT per-site, see docs/S8.6-decisions.md keying correction). `members` is
-- the ORDERED hub-capable gateway node-ids: members[0] = the active transit hub, the rest = failover
-- candidates in order. `generation` is the D5 FENCING TOKEN — monotonic, CP-persisted (survives restart —
-- a reset would un-fence every agent), bumped ONLY when `members` changes (a generation that ticks idly
-- erodes its fencing meaning). One row per org.
CREATE TABLE org_hub_set (
    org_id     uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    members    uuid[] NOT NULL,                    -- ordered: [primary, standby...]
    generation bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON org_hub_set
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
