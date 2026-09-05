ALTER TABLE k8s_connector_handoff_operations
    DROP CONSTRAINT k8s_handoff_operations_old_member_fkey,
    DROP CONSTRAINT k8s_handoff_operations_new_member_fkey;
ALTER TABLE pool_vip_ownership_deliveries
    DROP CONSTRAINT pool_vip_deliveries_connector_member_fkey,
    DROP CONSTRAINT pool_vip_deliveries_target_member_fkey;
ALTER TABLE pool_vip_ownership_delivery_states
    DROP CONSTRAINT pool_vip_delivery_states_connector_member_fkey;
ALTER TABLE k8s_pool_ownership_v2_capabilities
    DROP CONSTRAINT k8s_pool_ownership_capability_delivery_fkey;
ALTER TABLE pool_vip_ownership_handoff_provenance_capabilities
    DROP CONSTRAINT pool_vip_handoff_provenance_cap_delivery_fkey;
ALTER TABLE pool_vip_ownership_delivery_ack_receipts
    DROP CONSTRAINT pool_vip_delivery_ack_state_fkey;

ALTER TABLE k8s_connector_handoff_operations
    ADD CONSTRAINT k8s_handoff_operations_old_member_fkey
        FOREIGN KEY (pool_id, org_id, site_id, old_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id) ON DELETE RESTRICT,
    ADD CONSTRAINT k8s_handoff_operations_new_member_fkey
        FOREIGN KEY (pool_id, org_id, site_id, new_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id) ON DELETE RESTRICT;

ALTER TABLE pool_vip_ownership_deliveries
    ADD CONSTRAINT pool_vip_deliveries_connector_member_fkey
        FOREIGN KEY (pool_id, org_id, site_id, connector_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id) ON DELETE RESTRICT,
    ADD CONSTRAINT pool_vip_deliveries_target_member_fkey
        FOREIGN KEY (pool_id, org_id, site_id, target_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id) ON DELETE RESTRICT;

ALTER TABLE pool_vip_ownership_delivery_states
    ADD CONSTRAINT pool_vip_delivery_states_connector_member_fkey
        FOREIGN KEY (pool_id, org_id, site_id, connector_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id) ON DELETE RESTRICT;

ALTER TABLE k8s_pool_ownership_v2_capabilities
    ADD CONSTRAINT k8s_pool_ownership_capability_delivery_fkey
        FOREIGN KEY (delivery_row_id, org_id)
        REFERENCES pool_vip_ownership_deliveries (id, org_id) ON DELETE RESTRICT;

ALTER TABLE pool_vip_ownership_handoff_provenance_capabilities
    ADD CONSTRAINT pool_vip_handoff_provenance_cap_delivery_fkey
        FOREIGN KEY (delivery_row_id, org_id)
        REFERENCES pool_vip_ownership_deliveries (id, org_id) ON DELETE RESTRICT;

ALTER TABLE pool_vip_ownership_delivery_ack_receipts
    ADD CONSTRAINT pool_vip_delivery_ack_state_fkey
        FOREIGN KEY (state_id, org_id)
        REFERENCES pool_vip_ownership_delivery_states (id, org_id) ON DELETE RESTRICT;
