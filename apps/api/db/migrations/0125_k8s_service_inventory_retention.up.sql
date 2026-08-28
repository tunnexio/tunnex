-- S20.4 inventory retention: keep a bounded hot history without deleting the
-- exact immutable report used as durable initial-candidate evidence. The exact
-- report FK is created with the initial-candidate table in 0123, so this
-- migration remains a rolling-compatible retention-only expansion.

-- Only the security-definer retention function can mint a transaction-local
-- authorization. Ordinary INSERT/UPDATE/DELETE stays outside this narrow seam.
CREATE TABLE k8s_service_inventory_retention_authorizations (
    backend_pid     integer NOT NULL,
    transaction_id bigint NOT NULL,
    report_id       uuid PRIMARY KEY,
    created_at      timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON k8s_service_inventory_retention_authorizations FROM PUBLIC;

CREATE FUNCTION k8s_service_inventory_retention_authorized(target_report uuid)
RETURNS boolean AS $$
    SELECT EXISTS (
        SELECT 1
        FROM k8s_service_inventory_retention_authorizations auth_row
        WHERE auth_row.report_id=target_report
          AND auth_row.backend_pid=pg_backend_pid()
          AND auth_row.transaction_id=txid_current()
    );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path=public,pg_temp;
REVOKE ALL ON FUNCTION k8s_service_inventory_retention_authorized(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION k8s_service_inventory_snapshot_immutable() RETURNS trigger AS $$
DECLARE
    target_report uuid;
BEGIN
    IF TG_OP='DELETE' THEN
        IF TG_TABLE_NAME='k8s_service_inventory_reports' THEN
            target_report := OLD.id;
            IF k8s_service_inventory_retention_authorized(target_report)
               AND NOT EXISTS (
                   SELECT 1 FROM k8s_cluster_scope_initial_candidates candidate
                   WHERE candidate.inventory_report_id=target_report
               ) THEN
                RETURN OLD;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM k8s_clusters c WHERE c.id=OLD.cluster_id AND c.org_id=OLD.org_id) THEN
                RETURN OLD;
            END IF;
        ELSIF TG_TABLE_NAME='k8s_service_inventory_items' THEN
            target_report := OLD.report_id;
            IF k8s_service_inventory_retention_authorized(target_report) THEN
                RETURN OLD;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM k8s_service_inventory_reports r WHERE r.id=OLD.report_id) THEN
                RETURN OLD;
            END IF;
        ELSIF TG_TABLE_NAME='k8s_service_inventory_ports' THEN
            target_report := OLD.report_id;
            IF k8s_service_inventory_retention_authorized(target_report) THEN
                RETURN OLD;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM k8s_service_inventory_items i WHERE i.report_id=OLD.report_id AND i.inventory_ref=OLD.inventory_ref) THEN
                RETURN OLD;
            END IF;
        END IF;
    END IF;
    RAISE EXCEPTION 'k8s_service_inventory_snapshot_is_immutable';
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION k8s_service_inventory_prune(
    target_org uuid,
    target_cluster uuid,
    retain_unreferenced integer
) RETURNS bigint AS $$
DECLARE
    deleted_count bigint;
BEGIN
    IF retain_unreferenced <> 20 THEN
        RAISE EXCEPTION 'k8s_service_inventory_retention_bound_is_fixed_at_20';
    END IF;

    -- Serialize retention with inventory ingestion and cluster authority
    -- changes. A missing/mismatched cluster is an error, never empty success.
    PERFORM 1
    FROM k8s_clusters
    WHERE id=target_cluster AND org_id=target_org
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'k8s_service_inventory_retention_cluster_not_found';
    END IF;

    INSERT INTO k8s_service_inventory_retention_authorizations
        (backend_pid,transaction_id,report_id)
    SELECT pg_backend_pid(),txid_current(),ranked.id
    FROM (
        SELECT report.id,
               row_number() OVER (
                   ORDER BY report.received_at DESC,report.id DESC
               ) AS unreferenced_rank
        FROM k8s_service_inventory_reports report
        WHERE report.org_id=target_org AND report.cluster_id=target_cluster
          AND NOT EXISTS (
              SELECT 1
              FROM k8s_cluster_scope_initial_candidates candidate
              WHERE candidate.inventory_report_id=report.id
          )
    ) ranked
    WHERE ranked.unreferenced_rank>retain_unreferenced;

    DELETE FROM k8s_service_inventory_reports report
    USING k8s_service_inventory_retention_authorizations auth_row
    WHERE auth_row.report_id=report.id
      AND auth_row.backend_pid=pg_backend_pid()
      AND auth_row.transaction_id=txid_current();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;

    DELETE FROM k8s_service_inventory_retention_authorizations
    WHERE backend_pid=pg_backend_pid() AND transaction_id=txid_current();
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp;
REVOKE ALL ON FUNCTION k8s_service_inventory_prune(uuid,uuid,integer) FROM PUBLIC;
