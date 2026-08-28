-- Restore 0084's legacy-only selected-connector predicate. Observation rows
-- are retained; this rollback removes no provenance or replay history.
DROP TRIGGER k8s_service_uid_observation_require_selected_connector_before_progress
    ON k8s_service_uid_observation_replay_states;

CREATE OR REPLACE FUNCTION k8s_service_uid_observation_require_selected_connector() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM k8s_clusters c
        WHERE c.id = NEW.cluster_id
          AND c.org_id = NEW.org_id
          AND c.site_id = NEW.site_id
          AND c.connector_node_id = NEW.connector_node_id
    ) THEN
        RAISE EXCEPTION 'Kubernetes Service UID observation connector is not selected for cluster';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
