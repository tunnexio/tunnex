-- S10.3 Slice 2: a policy rule can target an exposed Kubernetes Service as its DESTINATION
-- (dst_kind='k8s_service'). The compiler resolves the Service's STABLE ID -> its CURRENT VIP at compile
-- time (never a snapshotted address), so a re-allocated VIP follows the identity and a deleted Service's
-- grant compiles to nothing. Mirrors the S8.1 site-dst cascade discipline (0033): a HARD delete of the
-- Service (e.g. its cluster removed) removes dependent grants (ON DELETE CASCADE); a SOFT delete keeps the
-- row so the grant survives and compiles to nothing (the honest "rule points at a vanished Service" surface
-- is the API/web slice).

ALTER TABLE policy_rules ADD COLUMN dst_k8s_service_id uuid REFERENCES k8s_services (id) ON DELETE CASCADE;

-- Widen dst_kind to include 'k8s_service' (0033 named this constraint policy_rules_dst_kind_check).
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource', 'group', 'site', 'k8s_service'));

-- Widen the exactly-one-dst CHECK (0033 named it policy_rules_check) to cover 'k8s_service'.
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind = 'resource'    AND dst_resource_id    IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
 OR (dst_kind = 'group'       AND dst_group_id       IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
 OR (dst_kind = 'site'        AND dst_site_id        IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_k8s_service_id IS NULL)
 OR (dst_kind = 'k8s_service' AND dst_k8s_service_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL));

-- Dedup: one grant per (src subject, dst Service), mirroring 0033's group/user × site uniques.
CREATE UNIQUE INDEX policy_rules_group_k8s_service_uniq ON policy_rules (org_id, src_group_id, dst_k8s_service_id)
    WHERE src_kind = 'group' AND dst_kind = 'k8s_service';
CREATE UNIQUE INDEX policy_rules_user_k8s_service_uniq ON policy_rules (org_id, src_user_id, dst_k8s_service_id)
    WHERE src_kind = 'user' AND dst_kind = 'k8s_service';
