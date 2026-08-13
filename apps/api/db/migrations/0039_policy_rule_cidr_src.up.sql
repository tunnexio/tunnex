-- S8.7 Slice 1: a policy rule can name a literal CIDR as its SOURCE (src_kind='cidr') — /32-precise grants,
-- the FINEST source subject (a single host in a site LAN, vs src_kind='site''s whole subnet: "172.31.17.64
-- may reach X, the rest of the site may not"). The compiler resolves the src CIDR to its CONTAINING site
-- subnet and places the grant on that site's gateway — the site-src path narrowed to the literal CIDR (ONE
-- emitter). src_cidr is plain text, validated in Go (netip.ParsePrefix) at creation; the DB CHECK backstops
-- the exactly-one-source invariant (refuse-don't-guess).
ALTER TABLE policy_rules ADD COLUMN src_cidr text;

-- Widen src_kind to include 'cidr' (0035's policy_rules_src_kind_check).
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_kind_check
    CHECK (src_kind IN ('group', 'user', 'site', 'cidr'));

-- Widen the exactly-one-src CHECK with the 'cidr' arm.
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_check CHECK (
    (src_kind = 'group' AND src_group_id IS NOT NULL AND src_user_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL)
 OR (src_kind = 'user'  AND src_user_id  IS NOT NULL AND src_group_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL)
 OR (src_kind = 'site'  AND src_site_id  IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_cidr IS NULL)
 OR (src_kind = 'cidr'  AND src_cidr     IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_site_id IS NULL));

-- Dedup: one grant per (src cidr, dst *), mirroring 0035's per-subject uniques.
CREATE UNIQUE INDEX policy_rules_cidr_resource_uniq ON policy_rules (org_id, src_cidr, dst_resource_id)
    WHERE src_kind = 'cidr' AND dst_kind = 'resource';
CREATE UNIQUE INDEX policy_rules_cidr_group_uniq ON policy_rules (org_id, src_cidr, dst_group_id)
    WHERE src_kind = 'cidr' AND dst_kind = 'group';
CREATE UNIQUE INDEX policy_rules_cidr_site_uniq ON policy_rules (org_id, src_cidr, dst_site_id)
    WHERE src_kind = 'cidr' AND dst_kind = 'site';
