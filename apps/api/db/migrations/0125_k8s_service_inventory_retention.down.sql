LOCK TABLE k8s_service_inventory_ports,
           k8s_service_inventory_items,
           k8s_service_inventory_reports,
           k8s_service_inventory_retention_authorizations
    IN ACCESS EXCLUSIVE MODE;

DROP FUNCTION k8s_service_inventory_prune(uuid,uuid,integer);
DROP FUNCTION k8s_service_inventory_retention_authorized(uuid);
DROP TABLE k8s_service_inventory_retention_authorizations;

CREATE OR REPLACE FUNCTION k8s_service_inventory_snapshot_immutable() RETURNS trigger AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        IF TG_TABLE_NAME='k8s_service_inventory_reports' THEN
            IF EXISTS (SELECT 1 FROM k8s_clusters c WHERE c.id=OLD.cluster_id AND c.org_id=OLD.org_id) THEN
                RAISE EXCEPTION 'k8s_service_inventory_snapshot_is_immutable';
            END IF;
        ELSIF TG_TABLE_NAME='k8s_service_inventory_items' THEN
            IF EXISTS (SELECT 1 FROM k8s_service_inventory_reports r WHERE r.id=OLD.report_id) THEN
                RAISE EXCEPTION 'k8s_service_inventory_snapshot_is_immutable';
            END IF;
        ELSIF TG_TABLE_NAME='k8s_service_inventory_ports' THEN
            IF EXISTS (SELECT 1 FROM k8s_service_inventory_items i WHERE i.report_id=OLD.report_id AND i.inventory_ref=OLD.inventory_ref) THEN
                RAISE EXCEPTION 'k8s_service_inventory_snapshot_is_immutable';
            END IF;
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'k8s_service_inventory_snapshot_is_immutable';
END;
$$ LANGUAGE plpgsql;
