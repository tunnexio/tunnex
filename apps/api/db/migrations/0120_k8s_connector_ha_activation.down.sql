-- Preservation-first contraction: application rollback keeps this additive
-- schema. Explicit down is allowed only before HA carries any state.
-- Lock every 0120 writer boundary before checking: otherwise a mixed-version
-- insert can commit after the emptiness read and be erased by the DROP.
LOCK TABLE k8s_base_authority_ack_receipts,
           k8s_base_authority_delivery_pools,
           k8s_base_authority_deliveries,
           k8s_base_authority_node_states,
           k8s_connector_pool_ha_transitions,
           k8s_ha_settings
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_ha_settings)
       OR EXISTS (SELECT 1 FROM k8s_connector_pool_ha_transitions)
       OR EXISTS (SELECT 1 FROM k8s_base_authority_node_states)
       OR EXISTS (SELECT 1 FROM k8s_base_authority_deliveries)
       OR EXISTS (SELECT 1 FROM k8s_base_authority_delivery_pools)
       OR EXISTS (SELECT 1 FROM k8s_base_authority_ack_receipts) THEN
        RAISE EXCEPTION 'cannot roll back 0120: Kubernetes connector HA state exists';
    END IF;
END;
$$;

DROP TABLE k8s_base_authority_ack_receipts;
DROP TABLE k8s_base_authority_delivery_pools;
DROP TABLE k8s_base_authority_deliveries;
DROP TABLE k8s_base_authority_node_states;
DROP TABLE k8s_connector_pool_ha_transitions;
DROP TABLE k8s_ha_settings;
DROP FUNCTION k8s_ha_actor_require_org_membership();
