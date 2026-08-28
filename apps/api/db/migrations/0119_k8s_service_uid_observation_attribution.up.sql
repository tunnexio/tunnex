-- S20.3a: bind each current Kubernetes Service UID incarnation to the exact
-- authenticated connector replay state that observed it. Existing current rows
-- remain intact but deliberately unattributed and therefore handoff-ineligible
-- until the selected connector reports them again.

CREATE TABLE k8s_service_uid_observation_current_attributions (
    ledger_id       uuid        NOT NULL,
    org_id          uuid        NOT NULL,
    namespace       text        NOT NULL,
    service         text        NOT NULL,
    replay_state_id uuid        NOT NULL,
    replay_sequence bigint      NOT NULL CHECK (replay_sequence > 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ledger_id, namespace, service),
    FOREIGN KEY (ledger_id, namespace, service)
        REFERENCES k8s_service_uid_observation_current (ledger_id, namespace, service) ON DELETE CASCADE,
    FOREIGN KEY (ledger_id, org_id)
        REFERENCES k8s_service_uid_observation_ledgers (id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (replay_state_id, org_id)
        REFERENCES k8s_service_uid_observation_replay_states (id, org_id) ON DELETE CASCADE
);
CREATE INDEX k8s_service_uid_observation_current_attributions_reporter_idx
    ON k8s_service_uid_observation_current_attributions (org_id, replay_state_id, replay_sequence);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_service_uid_observation_current_attributions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Any writer that changes a current row must re-assert reporter provenance in
-- the same transaction. This is the mixed-version fence: an older API can keep
-- writing 0084 rows, but its writes become unattributed instead of inheriting a
-- stale selected-connector claim.
CREATE FUNCTION k8s_service_uid_observation_invalidate_current_attribution() RETURNS trigger AS $$
BEGIN
    DELETE FROM k8s_service_uid_observation_current_attributions a
    WHERE a.ledger_id=NEW.ledger_id AND a.namespace=NEW.namespace AND a.service=NEW.service;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_service_uid_observation_invalidate_current_attribution_after_write
    AFTER INSERT OR UPDATE OF org_id, uid, state, replay_sequence
    ON k8s_service_uid_observation_current
    FOR EACH ROW EXECUTE FUNCTION k8s_service_uid_observation_invalidate_current_attribution();

-- Raw SQL receives the same exact reporter/scope fence as the Go store. The
-- row locks make selection, promotion, revocation, key and endpoint changes
-- serialize with attribution creation rather than racing its statement snapshot.
CREATE FUNCTION k8s_service_uid_observation_require_current_attribution() RETURNS trigger AS $$
BEGIN
    PERFORM 1
    FROM k8s_service_uid_observation_current current_uid
    JOIN k8s_service_uid_observation_ledgers l
      ON l.id=current_uid.ledger_id AND l.org_id=current_uid.org_id
    JOIN k8s_service_uid_observation_replay_states r
      ON r.id=NEW.replay_state_id AND r.org_id=NEW.org_id
     AND r.site_id=l.site_id AND r.cluster_id=l.cluster_id
    JOIN k8s_clusters c
      ON c.id=l.cluster_id AND c.org_id=l.org_id AND c.site_id=l.site_id
    JOIN nodes n
      ON n.id=r.connector_node_id AND n.org_id=r.org_id AND n.site_id=r.site_id
    WHERE current_uid.ledger_id=NEW.ledger_id
      AND current_uid.org_id=NEW.org_id
      AND current_uid.namespace=NEW.namespace
      AND current_uid.service=NEW.service
      AND current_uid.replay_sequence=NEW.replay_sequence
      AND r.sequence = NEW.replay_sequence
      AND c.connector_pool_id IS NULL
      AND c.connector_node_id=r.connector_node_id
      AND n.status='active' AND n.revoked_at IS NULL
    FOR SHARE OF current_uid,l,r,c,n;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM k8s_service_uid_observation_current current_uid
    JOIN k8s_service_uid_observation_ledgers l
      ON l.id=current_uid.ledger_id AND l.org_id=current_uid.org_id
    JOIN k8s_service_uid_observation_replay_states r
      ON r.id=NEW.replay_state_id AND r.org_id=NEW.org_id
     AND r.site_id=l.site_id AND r.cluster_id=l.cluster_id
    JOIN k8s_clusters c
      ON c.id=l.cluster_id AND c.org_id=l.org_id AND c.site_id=l.site_id
    JOIN k8s_connector_pools p
      ON p.id=c.connector_pool_id AND p.org_id=c.org_id AND p.site_id=c.site_id AND p.cluster_id=c.id
    JOIN k8s_connector_pool_members m
      ON m.pool_id=p.id AND m.org_id=p.org_id AND m.site_id=p.site_id AND m.node_id=r.connector_node_id
    JOIN nodes n
      ON n.id=m.node_id AND n.org_id=m.org_id AND n.site_id=m.site_id
    WHERE current_uid.ledger_id=NEW.ledger_id
      AND current_uid.org_id=NEW.org_id
      AND current_uid.namespace=NEW.namespace
      AND current_uid.service=NEW.service
      AND current_uid.replay_sequence=NEW.replay_sequence
      AND r.sequence = NEW.replay_sequence
      AND c.connector_node_id IS NULL
      AND p.active_node_id=r.connector_node_id
      AND p.generation > 0
      AND n.status='active' AND n.revoked_at IS NULL
      AND n.wg_public_key ~ '^[A-Za-z0-9+/]{43}=$'
      AND btrim(n.endpoint) <> ''
    FOR SHARE OF current_uid,l,r,c,p,m,n;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Kubernetes Service UID current attribution is not from the selected eligible connector';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_service_uid_observation_require_current_attribution_before_write
    BEFORE INSERT OR UPDATE ON k8s_service_uid_observation_current_attributions
    FOR EACH ROW EXECUTE FUNCTION k8s_service_uid_observation_require_current_attribution();

-- 0118 allowed a Service UID child to cite any matching cluster-wide current
-- row. Preserve its v2/v3 capability behavior, but require new UID children to
-- cite the exact selected active reporter attribution introduced above.
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
            JOIN k8s_service_uid_observation_ledgers l
              ON l.org_id=NEW.org_id AND l.site_id=NEW.site_id AND l.cluster_id=NEW.cluster_id
            JOIN k8s_service_uid_observation_current c
              ON c.ledger_id=l.id AND c.org_id=l.org_id
            JOIN k8s_service_uid_observation_current_attributions attribution
              ON attribution.ledger_id=c.ledger_id AND attribution.org_id=c.org_id
             AND attribution.namespace=c.namespace AND attribution.service=c.service
             AND attribution.replay_sequence=c.replay_sequence
            JOIN k8s_service_uid_observation_replay_states replay
              ON replay.id=attribution.replay_state_id AND replay.org_id=attribution.org_id
             AND replay.site_id=l.site_id AND replay.cluster_id=l.cluster_id
            WHERE p.operation_id=NEW.operation_id AND p.org_id=NEW.org_id AND p.site_id=NEW.site_id
              AND p.cluster_id=NEW.cluster_id AND p.pool_id=NEW.pool_id
              AND NEW.active_node_id=p.old_node_id AND NEW.promotion_generation=p.expected_generation
              AND replay.connector_node_id=NEW.active_node_id
              AND c.namespace=NEW.namespace AND c.service=NEW.service AND c.uid=NEW.service_uid
              AND c.state='live' AND c.replay_sequence=NEW.observation_revision
        ) THEN
            RAISE EXCEPTION 'pool VIP ownership handoff provenance Service UID child scope is invalid';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
