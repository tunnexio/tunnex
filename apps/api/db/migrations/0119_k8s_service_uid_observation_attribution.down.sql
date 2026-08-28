-- Reporter attribution is handoff authority. Refuse a contraction that would
-- silently turn attributed observations back into ambiguous cluster-wide rows.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_service_uid_observation_current_attributions) THEN
        RAISE EXCEPTION 'cannot remove Kubernetes Service UID attribution while attributed observations exist';
    END IF;
END $$;

-- Restore the exact 0118 child predicate before removing the attribution
-- schema. Existing v2/v3 capability rows and current UID rows are preserved.
CREATE OR REPLACE FUNCTION pool_vip_ownership_handoff_provenance_require_child_scope() RETURNS trigger AS $$
BEGIN
    IF TG_TABLE_NAME = 'pool_vip_ownership_handoff_provenance_capabilities' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM pool_vip_ownership_handoff_provenance p
            JOIN pool_vip_ownership_deliveries d ON d.id=NEW.delivery_row_id AND d.org_id=NEW.org_id
            JOIN pool_vip_ownership_delivery_ack_receipts a ON a.delivery_row_id=d.id AND a.org_id=d.org_id
            JOIN nodes n ON n.id=d.target_node_id AND n.org_id=d.org_id AND n.site_id=d.site_id
            WHERE p.operation_id=NEW.operation_id AND p.org_id=NEW.org_id AND p.site_id=NEW.site_id
              AND p.cluster_id=NEW.cluster_id AND p.pool_id=NEW.pool_id
              AND NEW.node_id IN (p.old_node_id, p.new_node_id)
              AND d.site_id=NEW.site_id AND d.cluster_id=NEW.cluster_id AND d.pool_id=NEW.pool_id
              AND d.connector_node_id=NEW.node_id AND d.target_node_id=NEW.node_id
              AND d.wire_version=NEW.wire_version
              AND n.status='active' AND n.revoked_at IS NULL
              AND a.applied_role=d.role
              AND a.applied_manifest_identity=d.manifest_identity
              AND a.applied_promotion_generation=d.promotion_generation
              AND a.applied_manifest_revision=d.manifest_revision
              AND a.owned_route_digest=d.expected_route_digest
              AND a.applied_lease_epoch=CASE WHEN d.role='withdrawal' THEN d.prior_lease_epoch ELSE d.lease_epoch END
              AND ((d.role='serving' AND a.vip_map_digest=d.expected_vip_map_digest)
                   OR (d.role IN ('prepared_non_serving','withdrawal') AND a.vip_map_digest=''))
              AND (
                  (NEW.wire_version=2 AND a.applied_manifest IS NULL AND d.ownership_manifest='{}'::jsonb)
                  OR
                  (NEW.wire_version=3 AND a.applied_manifest=d.ownership_manifest
                   AND a.applied_manifest IS NOT NULL AND d.ownership_manifest<>'{}'::jsonb)
              )
              AND a.receipt_time=NEW.receipt_time AND d.expires_at=NEW.expires_at
              AND a.receipt_time >= now() - interval '5 minutes'
              AND a.receipt_time <= now() + interval '5 seconds'
              AND d.expires_at > now()
        ) THEN
            RAISE EXCEPTION 'pool VIP ownership handoff provenance capability child scope is invalid';
        END IF;
    ELSE
        IF NOT EXISTS (
            SELECT 1
            FROM pool_vip_ownership_handoff_provenance p
            JOIN k8s_service_uid_observation_ledgers l ON l.org_id=NEW.org_id AND l.site_id=NEW.site_id AND l.cluster_id=NEW.cluster_id
            JOIN k8s_service_uid_observation_current c ON c.ledger_id=l.id AND c.org_id=l.org_id
            WHERE p.operation_id=NEW.operation_id AND p.org_id=NEW.org_id AND p.site_id=NEW.site_id
              AND p.cluster_id=NEW.cluster_id AND p.pool_id=NEW.pool_id
              AND NEW.active_node_id=p.old_node_id AND NEW.promotion_generation=p.expected_generation
              AND c.namespace=NEW.namespace AND c.service=NEW.service AND c.uid=NEW.service_uid
              AND c.state='live' AND c.replay_sequence=NEW.observation_revision
        ) THEN
            RAISE EXCEPTION 'pool VIP ownership handoff provenance Service UID child scope is invalid';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER k8s_service_uid_observation_require_current_attribution_before_write
    ON k8s_service_uid_observation_current_attributions;
DROP FUNCTION k8s_service_uid_observation_require_current_attribution();

DROP TRIGGER k8s_service_uid_observation_invalidate_current_attribution_after_write
    ON k8s_service_uid_observation_current;
DROP FUNCTION k8s_service_uid_observation_invalidate_current_attribution();

DROP TABLE k8s_service_uid_observation_current_attributions;
