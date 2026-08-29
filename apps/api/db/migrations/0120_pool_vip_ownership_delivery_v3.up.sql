-- S20.3a: additive durable payload for the first handoff-authoritative wire
-- version. v1 stays receipt-only and v2 stays route/VIP-digest attestation;
-- neither is silently upgraded to lease authority.

ALTER TABLE pool_vip_ownership_deliveries
    ADD COLUMN ownership_manifest jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE pool_vip_ownership_deliveries
    DROP CONSTRAINT pool_vip_ownership_deliveries_wire_version_check,
    DROP CONSTRAINT pool_vip_ownership_deliveries_check;

ALTER TABLE pool_vip_ownership_deliveries
    ADD CONSTRAINT pool_vip_ownership_deliveries_wire_version_check
        CHECK (wire_version IN (1, 2, 3)),
    ADD CONSTRAINT pool_vip_ownership_deliveries_version_payload_check CHECK (
        (
            wire_version = 1
            AND owned_routes = '[]'::jsonb
            AND expected_route_digest = ''
            AND expected_vip_map_digest = ''
            AND prior_lease_epoch = 0
            AND ownership_manifest = '{}'::jsonb
        )
        OR
        (
            wire_version = 2
            AND jsonb_typeof(owned_routes) = 'array'
            AND expected_route_digest ~ '^[0-9a-f]{64}$'
            AND (expected_vip_map_digest = '' OR expected_vip_map_digest ~ '^[0-9a-f]{64}$')
            AND ownership_manifest = '{}'::jsonb
        )
        OR
        (
            wire_version = 3
            AND jsonb_typeof(owned_routes) = 'array'
            AND expected_route_digest ~ '^[0-9a-f]{64}$'
            AND (expected_vip_map_digest = '' OR expected_vip_map_digest ~ '^[0-9a-f]{64}$')
            AND jsonb_typeof(ownership_manifest) = 'object'
            AND ownership_manifest <> '{}'::jsonb
            AND octet_length(ownership_manifest::text) <= 12288
            AND (
                (role = 'serving' AND prior_lease_epoch = 0 AND expected_vip_map_digest ~ '^[0-9a-f]{64}$')
                OR
                (role = 'prepared_non_serving' AND prior_lease_epoch = 0 AND expected_vip_map_digest = '')
                OR
                (role = 'withdrawal' AND prior_lease_epoch > 0 AND expected_vip_map_digest = '')
            )
        )
    );

ALTER TABLE pool_vip_ownership_delivery_ack_receipts
    ADD COLUMN applied_manifest jsonb,
    ADD CONSTRAINT pool_vip_ownership_delivery_ack_receipts_manifest_check CHECK (
        applied_manifest IS NULL
        OR (
            jsonb_typeof(applied_manifest) = 'object'
            AND applied_manifest <> '{}'::jsonb
            AND octet_length(applied_manifest::text) <= 12288
        )
    );

-- Keep the generic receipt table version-coherent even when a future caller
-- writes it outside the Go store: v1/v2 may not smuggle a full-manifest claim,
-- and v3 may not persist an ACK without the exact applied manifest.
CREATE FUNCTION pool_vip_ownership_ack_manifest_matches_wire_version() RETURNS trigger AS $$
DECLARE
    delivery_wire_version integer;
BEGIN
    SELECT d.wire_version INTO delivery_wire_version
    FROM pool_vip_ownership_deliveries d
    WHERE d.id=NEW.delivery_row_id AND d.org_id=NEW.org_id;
    IF delivery_wire_version IS NULL
       OR (delivery_wire_version IN (1, 2) AND NEW.applied_manifest IS NOT NULL)
       OR (delivery_wire_version = 3 AND NEW.applied_manifest IS NULL) THEN
        RAISE EXCEPTION 'ownership acknowledgement manifest does not match delivery wire version';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER pool_vip_ownership_ack_manifest_matches_wire_version_before_write
    BEFORE INSERT OR UPDATE OF org_id, delivery_row_id, applied_manifest
    ON pool_vip_ownership_delivery_ack_receipts
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_ack_manifest_matches_wire_version();

-- Keep the historical table name for rolling compatibility, but expand its
-- payload contract. Existing v2 observations remain readable; only an exact
-- v3 row is eligible for the new handoff scheduler.
ALTER TABLE k8s_pool_ownership_v2_capabilities
    DROP CONSTRAINT k8s_pool_ownership_v2_capabilities_wire_version_check,
    ADD CONSTRAINT k8s_pool_ownership_v2_capabilities_wire_version_check
        CHECK (wire_version IN (2, 3));

CREATE OR REPLACE FUNCTION k8s_pool_ownership_v2_capability_require_member() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM k8s_connector_pool_members m
        WHERE m.pool_id=NEW.pool_id AND m.org_id=NEW.org_id AND m.site_id=NEW.site_id
          AND m.node_id=NEW.node_id
    ) THEN
        RAISE EXCEPTION 'pool ownership capability node is not a pool member';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pool_vip_ownership_deliveries d
        JOIN pool_vip_ownership_delivery_ack_receipts a
          ON a.delivery_row_id=d.id AND a.org_id=d.org_id
        JOIN nodes n ON n.id=d.target_node_id AND n.org_id=d.org_id AND n.site_id=d.site_id
        WHERE d.id=NEW.delivery_row_id AND d.org_id=NEW.org_id
          AND d.site_id=NEW.site_id AND d.cluster_id=NEW.cluster_id AND d.pool_id=NEW.pool_id
          AND d.target_node_id=NEW.node_id AND d.connector_node_id=NEW.node_id
          AND n.status='active' AND n.revoked_at IS NULL
          AND d.wire_version=NEW.wire_version
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
        RAISE EXCEPTION 'pool ownership capability lacks fresh applied-state evidence';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- The operation-scoped child snapshot is also a rolling-compatibility table.
-- Retain its released v2 rows, but permit an exact v3 receipt to be snapshotted
-- for new handoff authority. 0085 declared this CHECK inline, so PostgreSQL
-- truncated its generated 69-byte name to the exact 63-byte identifier below.
-- Replace it with an explicit short name so later migrations never depend on
-- identifier truncation again.
ALTER TABLE pool_vip_ownership_handoff_provenance_capabilities
    DROP CONSTRAINT pool_vip_ownership_handoff_provenance_capabi_wire_version_check,
    ADD CONSTRAINT pool_vip_handoff_provenance_caps_wire_version_check
        CHECK (wire_version IN (2, 3));

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
