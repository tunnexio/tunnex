-- S8.1 Slice 3: a policy rule can target a SITE as its DESTINATION (dst_kind='site'). The compiler
-- resolves the site to its subnet CIDR(s) CP-side (Option A: no new wire field — a device→site-subnet
-- grant is a plain AllowEntry{Src, Dst: site-subnet-CIDR}). Mirrors the S7.1 resource/group dst cascade
-- discipline (0018): deleting a site must remove its dependent grants (no dangling grant to a vanished
-- site), so dst_site_id -> sites ON DELETE CASCADE.

ALTER TABLE policy_rules ADD COLUMN dst_site_id uuid REFERENCES sites (id) ON DELETE CASCADE;

-- Widen dst_kind to include 'site' (the 0018 CHECK is unnamed: policy_rules_dst_kind_check).
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource', 'group', 'site'));

-- Widen the exactly-one-dst CHECK (0018 unnamed: policy_rules_check) to cover 'site'.
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind = 'resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL)
 OR (dst_kind = 'group'    AND dst_group_id    IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL)
 OR (dst_kind = 'site'     AND dst_site_id     IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL));

-- Dedup: one grant per (src subject, dst site), mirroring 0030's group/user × resource/group uniques.
CREATE UNIQUE INDEX policy_rules_group_site_uniq ON policy_rules (org_id, src_group_id, dst_site_id)
    WHERE src_kind = 'group' AND dst_kind = 'site';
CREATE UNIQUE INDEX policy_rules_user_site_uniq ON policy_rules (org_id, src_user_id, dst_site_id)
    WHERE src_kind = 'user' AND dst_kind = 'site';
