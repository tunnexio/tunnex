-- Pool deletion cascades through several dependent tables at once. RESTRICT
-- checks are immediate and can reject that valid graph teardown depending on
-- trigger order. Deferred NO ACTION preserves the important standalone-delete
-- refusal while allowing the complete pool-owned graph to be gone by commit.
DO $$
DECLARE
    fk record;
    dropped integer := 0;
BEGIN
    FOR fk IN
        SELECT c.conrelid::regclass AS child_table, c.conname
        FROM pg_constraint c
        WHERE c.contype = 'f'
          AND (
            (c.conrelid = 'k8s_connector_handoff_operations'::regclass
             AND c.confrelid = 'k8s_connector_pool_members'::regclass)
            OR (c.conrelid = 'pool_vip_ownership_deliveries'::regclass
                AND c.confrelid = 'k8s_connector_pool_members'::regclass)
            OR (c.conrelid = 'pool_vip_ownership_delivery_states'::regclass
                AND c.confrelid = 'k8s_connector_pool_members'::regclass)
            OR (c.conrelid = 'k8s_pool_ownership_v2_capabilities'::regclass
                AND c.confrelid = 'pool_vip_ownership_deliveries'::regclass)
            OR (c.conrelid = 'pool_vip_ownership_handoff_provenance_capabilities'::regclass
                AND c.confrelid = 'pool_vip_ownership_deliveries'::regclass)
            OR (c.conrelid = 'pool_vip_ownership_delivery_ack_receipts'::regclass
                AND c.confrelid = 'pool_vip_ownership_delivery_states'::regclass)
          )
    LOOP
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', fk.child_table, fk.conname);
        dropped := dropped + 1;
    END LOOP;

    IF dropped <> 8 THEN
        RAISE EXCEPTION 'expected 8 internal pool-descendant FKs, found %', dropped;
    END IF;
END;
$$;

ALTER TABLE k8s_connector_handoff_operations
    ADD CONSTRAINT k8s_handoff_operations_old_member_fkey
        FOREIGN KEY (pool_id, org_id, site_id, old_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT k8s_handoff_operations_new_member_fkey
        FOREIGN KEY (pool_id, org_id, site_id, new_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE pool_vip_ownership_deliveries
    ADD CONSTRAINT pool_vip_deliveries_connector_member_fkey
        FOREIGN KEY (pool_id, org_id, site_id, connector_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT pool_vip_deliveries_target_member_fkey
        FOREIGN KEY (pool_id, org_id, site_id, target_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE pool_vip_ownership_delivery_states
    ADD CONSTRAINT pool_vip_delivery_states_connector_member_fkey
        FOREIGN KEY (pool_id, org_id, site_id, connector_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE k8s_pool_ownership_v2_capabilities
    ADD CONSTRAINT k8s_pool_ownership_capability_delivery_fkey
        FOREIGN KEY (delivery_row_id, org_id)
        REFERENCES pool_vip_ownership_deliveries (id, org_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE pool_vip_ownership_handoff_provenance_capabilities
    ADD CONSTRAINT pool_vip_handoff_provenance_cap_delivery_fkey
        FOREIGN KEY (delivery_row_id, org_id)
        REFERENCES pool_vip_ownership_deliveries (id, org_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE pool_vip_ownership_delivery_ack_receipts
    ADD CONSTRAINT pool_vip_delivery_ack_state_fkey
        FOREIGN KEY (state_id, org_id)
        REFERENCES pool_vip_ownership_delivery_states (id, org_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;
