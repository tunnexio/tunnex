-- S8.2 Slice 1: a policy rule can name a SITE's LAN as its SOURCE (src_kind='site'). This is the
-- enforcement half of site-to-site — a site's advertised subnets become a policy SUBJECT, symmetric to
-- S8.1's dst_kind='site' (0033). The compiler resolves the source site to its subnet CIDR(s) CP-side and
-- emits AllowEntry{Src: site-subnet-CIDR, Dst: ...}; the source is a CIDR, not a device /32 (the agent's
-- allowMatch widens ParseAddr->ParsePrefix to match it). Mirrors the dst cascade discipline: deleting a
-- site must remove its dependent grants, so src_site_id -> sites ON DELETE CASCADE.

ALTER TABLE policy_rules ADD COLUMN src_site_id uuid REFERENCES sites (id) ON DELETE CASCADE;

-- Widen src_kind to include 'site' (0030's unnamed CHECK: policy_rules_src_kind_check).
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_kind_check
    CHECK (src_kind IN ('group', 'user', 'site'));

-- Widen the exactly-one-src CHECK (0030's policy_rules_src_check covered group|user only) to add the
-- 'site' arm, so a malformed row is a loud 23514, not a silent mis-source (refuse-don't-guess).
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_check CHECK (
    (src_kind = 'group' AND src_group_id IS NOT NULL AND src_user_id IS NULL AND src_site_id IS NULL)
 OR (src_kind = 'user'  AND src_user_id  IS NOT NULL AND src_group_id IS NULL AND src_site_id IS NULL)
 OR (src_kind = 'site'  AND src_site_id  IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL));

-- Dedup: one grant per (src site, dst *), mirroring 0030/0033's per-subject uniques. A site source can
-- target a resource, a group, or another site.
CREATE UNIQUE INDEX policy_rules_site_resource_uniq ON policy_rules (org_id, src_site_id, dst_resource_id)
    WHERE src_kind = 'site' AND dst_kind = 'resource';
CREATE UNIQUE INDEX policy_rules_site_group_uniq ON policy_rules (org_id, src_site_id, dst_group_id)
    WHERE src_kind = 'site' AND dst_kind = 'group';
CREATE UNIQUE INDEX policy_rules_site_site_uniq ON policy_rules (org_id, src_site_id, dst_site_id)
    WHERE src_kind = 'site' AND dst_kind = 'site';
