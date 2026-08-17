-- Never discard newly persisted origin provenance. Existing legacy NULL rows
-- are safe to retain because they predate this schema and remain status-only.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_cluster_scope_memberships WHERE origin IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot rollback 0087 with persisted cluster-scope membership origin data';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS k8s_cluster_scope_memberships_origin_before_write ON k8s_cluster_scope_memberships;
DROP FUNCTION IF EXISTS k8s_cluster_scope_membership_origin_require_immutable();
ALTER TABLE k8s_cluster_scope_memberships DROP COLUMN origin;
