-- Replay and cluster-incarnation authority jointly prevent stale UID revival.
-- Rolling either back with data would reopen that fence, so refuse loudly.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_service_uid_observation_replay_states)
       OR EXISTS (SELECT 1 FROM k8s_service_uid_observation_ledgers)
       OR EXISTS (SELECT 1 FROM k8s_service_uid_observation_receipts)
       OR EXISTS (SELECT 1 FROM k8s_service_uid_observation_current)
       OR EXISTS (SELECT 1 FROM k8s_service_uid_observation_retired) THEN
        RAISE EXCEPTION 'cannot roll back 0084: Kubernetes Service UID observation ledger contains data';
    END IF;
END;
$$;

DROP TRIGGER k8s_service_uid_observation_bound_retired_before_insert ON k8s_service_uid_observation_retired;
DROP FUNCTION k8s_service_uid_observation_bound_retired();
DROP TABLE k8s_service_uid_observation_retired;
DROP TABLE k8s_service_uid_observation_current;
DROP TABLE k8s_service_uid_observation_receipts;
DROP TRIGGER k8s_service_uid_observation_require_selected_connector_before_write ON k8s_service_uid_observation_replay_states;
DROP FUNCTION k8s_service_uid_observation_require_selected_connector();
DROP TABLE k8s_service_uid_observation_ledgers;
DROP TABLE k8s_service_uid_observation_replay_states;
ALTER TABLE k8s_clusters DROP CONSTRAINT k8s_clusters_connector_node_org_site_k8s_uid_observation_fk;
