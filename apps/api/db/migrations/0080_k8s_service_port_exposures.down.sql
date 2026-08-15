-- A rollback is safe only before multi-port data exists. Collapsing children
-- would either discard an exposure or silently widen a grant, so refuse loudly.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM k8s_services
        WHERE deleted_at IS NULL
        GROUP BY identity_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot roll back 0080: live Kubernetes Service identities have multiple port exposures';
    END IF;
END;
$$;

DROP TRIGGER k8s_services_retire_identity_after_update ON k8s_services;
DROP FUNCTION k8s_services_retire_identity();
DROP TRIGGER k8s_services_enforce_identity_before_update ON k8s_services;
DROP FUNCTION k8s_services_enforce_identity();
DROP TRIGGER k8s_services_bind_identity_before_insert ON k8s_services;
DROP FUNCTION k8s_services_bind_identity();
DROP INDEX k8s_services_identity_live_idx;
DROP INDEX k8s_services_port_exposure_live;
CREATE UNIQUE INDEX k8s_services_ident_live ON k8s_services (cluster_id, namespace, name)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX k8s_services_vip_live ON k8s_services (cluster_id, vip)
    WHERE deleted_at IS NULL;
ALTER TABLE k8s_services DROP CONSTRAINT k8s_services_identity_vip_fk;
ALTER TABLE k8s_services DROP CONSTRAINT k8s_services_identity_required;
ALTER TABLE k8s_services DROP COLUMN identity_id;
DROP TABLE k8s_service_identities;
