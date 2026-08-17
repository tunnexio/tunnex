-- S10.3 P2: immutable pre-issuance provenance for an unregistered P1/P2
-- handoff bridge. This migration follows 0084 and depends on 0079 pools,
-- 0081 delivery identities, 0082 durable operation identities, and 0084's
-- cluster-scoped Service-UID ledger. It never derives fresh authority from an
-- issued delivery or an agent capability header.

CREATE TABLE k8s_pool_ownership_v2_capabilities (
    org_id          uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid        NOT NULL,
    cluster_id      uuid        NOT NULL,
    pool_id         uuid        NOT NULL,
    node_id         uuid        NOT NULL,
    wire_version    integer     NOT NULL CHECK (wire_version = 2),
    delivery_row_id uuid        NOT NULL,
    receipt_time    timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, pool_id, node_id),
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
        REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id) ON DELETE CASCADE,
    FOREIGN KEY (node_id, org_id, site_id)
        REFERENCES nodes (id, org_id, site_id) ON DELETE CASCADE,
    FOREIGN KEY (delivery_row_id, org_id)
        REFERENCES pool_vip_ownership_deliveries (id, org_id) ON DELETE RESTRICT
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_pool_ownership_v2_capabilities
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE FUNCTION k8s_pool_ownership_v2_capability_require_member() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM k8s_connector_pool_members m
        WHERE m.pool_id=NEW.pool_id AND m.org_id=NEW.org_id AND m.site_id=NEW.site_id
          AND m.node_id=NEW.node_id
    ) THEN
        RAISE EXCEPTION 'pool ownership v2 capability node is not a pool member';
    END IF;
    -- Capability is not an advertised header. It is one exact, authenticated
    -- v2 applied-state receipt for this member, still unexpired and inside the
    -- intentionally short CP-receipt freshness window.
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
          AND d.wire_version=2
          AND a.applied_role=d.role
          AND a.applied_manifest_identity=d.manifest_identity
          AND a.applied_promotion_generation=d.promotion_generation
          AND a.applied_manifest_revision=d.manifest_revision
          AND a.owned_route_digest=d.expected_route_digest
          AND a.applied_lease_epoch=CASE WHEN d.role='withdrawal' THEN d.prior_lease_epoch ELSE d.lease_epoch END
          AND ((d.role='serving' AND a.vip_map_digest=d.expected_vip_map_digest)
               OR (d.role IN ('prepared_non_serving','withdrawal') AND a.vip_map_digest=''))
          AND a.receipt_time=NEW.receipt_time AND d.expires_at=NEW.expires_at
          AND a.receipt_time >= now() - interval '5 minutes'
          AND a.receipt_time <= now() + interval '5 seconds'
          AND d.expires_at > now()
    ) THEN
        RAISE EXCEPTION 'pool ownership v2 capability lacks fresh applied-state evidence';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_pool_ownership_v2_capability_require_member_before_write
    BEFORE INSERT OR UPDATE OF org_id, site_id, cluster_id, pool_id, node_id, wire_version, delivery_row_id, receipt_time, expires_at
    ON k8s_pool_ownership_v2_capabilities
    FOR EACH ROW EXECUTE FUNCTION k8s_pool_ownership_v2_capability_require_member();

-- A live UID incarnation is selected at claim time and bound to the exact
-- pool active node/generation. This record is evidence for P2's provenance
-- writer only; it is not public approval state.
CREATE TABLE k8s_pool_service_uid_provenance (
    org_id              uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id             uuid        NOT NULL,
    cluster_id          uuid        NOT NULL,
    pool_id             uuid        NOT NULL,
    active_node_id      uuid        NOT NULL,
    promotion_generation bigint     NOT NULL CHECK (promotion_generation > 0),
    ledger_id           uuid        NOT NULL,
    namespace           text        NOT NULL CHECK (namespace ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND octet_length(namespace) BETWEEN 1 AND 63),
    service             text        NOT NULL CHECK (service ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND octet_length(service) BETWEEN 1 AND 63),
    service_uid         text        NOT NULL CHECK (octet_length(service_uid) BETWEEN 1 AND 253 AND service_uid !~ '[[:cntrl:]]'),
    observation_revision bigint     NOT NULL CHECK (observation_revision > 0),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, pool_id, promotion_generation, namespace, service),
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
        REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id) ON DELETE CASCADE,
    FOREIGN KEY (active_node_id, org_id, site_id)
        REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT,
    FOREIGN KEY (ledger_id, org_id)
        REFERENCES k8s_service_uid_observation_ledgers (id, org_id) ON DELETE CASCADE
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_pool_service_uid_provenance
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE FUNCTION k8s_pool_service_uid_provenance_require_current() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM k8s_connector_pools p
        WHERE p.id=NEW.pool_id AND p.org_id=NEW.org_id AND p.site_id=NEW.site_id
          AND p.cluster_id=NEW.cluster_id AND p.active_node_id=NEW.active_node_id
          AND p.generation=NEW.promotion_generation
    ) THEN
        RAISE EXCEPTION 'pool Service UID provenance does not match active node/generation';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM k8s_service_uid_observation_ledgers l
        JOIN k8s_service_uid_observation_current c ON c.ledger_id=l.id AND c.org_id=l.org_id
        WHERE l.id=NEW.ledger_id AND l.org_id=NEW.org_id AND l.site_id=NEW.site_id
          AND l.cluster_id=NEW.cluster_id AND c.namespace=NEW.namespace AND c.service=NEW.service
          AND c.uid=NEW.service_uid AND c.state='live' AND c.replay_sequence=NEW.observation_revision
    ) THEN
        RAISE EXCEPTION 'pool Service UID provenance is not a current cluster incarnation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_pool_service_uid_provenance_require_current_before_write
    BEFORE INSERT OR UPDATE OF org_id, site_id, cluster_id, pool_id, active_node_id,
      promotion_generation, ledger_id, namespace, service, service_uid, observation_revision
    ON k8s_pool_service_uid_provenance
    FOR EACH ROW EXECUTE FUNCTION k8s_pool_service_uid_provenance_require_current();

-- Raw v2 envelopes (including route arrays) are retained only inside P2's
-- private store. P1 receives the parsed non-secret identities and digests
-- through the facade, never these JSON bodies.
CREATE TABLE pool_vip_ownership_handoff_provenance (
    operation_id       uuid        PRIMARY KEY,
    org_id             uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id            uuid        NOT NULL,
    cluster_id         uuid        NOT NULL,
    pool_id            uuid        NOT NULL,
    old_node_id        uuid        NOT NULL,
    new_node_id        uuid        NOT NULL,
    expected_generation bigint     NOT NULL CHECK (expected_generation > 0),
    target_generation   bigint     NOT NULL CHECK (target_generation = expected_generation + 1),
    decision_transition text        NOT NULL CHECK (decision_transition IN ('promoted', 'failed_back')),
    old_lease_identity  text        NOT NULL CHECK (octet_length(old_lease_identity) BETWEEN 1 AND 512 AND btrim(old_lease_identity) <> ''),
    target_lease_identity text      NOT NULL CHECK (octet_length(target_lease_identity) BETWEEN 1 AND 512 AND btrim(target_lease_identity) <> ''),
    membership_snapshot uuid[]     NOT NULL CHECK (cardinality(membership_snapshot) BETWEEN 2 AND 512),
    old_serving_envelope jsonb     NOT NULL,
    new_prepared_envelope jsonb    NOT NULL,
    old_withdrawal_envelope jsonb  NOT NULL,
    new_serving_envelope jsonb     NOT NULL,
    old_serving_expires_at timestamptz NOT NULL,
    new_prepared_expires_at timestamptz NOT NULL,
    old_withdrawal_expires_at timestamptz NOT NULL,
    new_serving_expires_at timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (operation_id, org_id),
    UNIQUE (operation_id, org_id, site_id, cluster_id, pool_id),
    CHECK (old_node_id <> new_node_id),
    CHECK (jsonb_typeof(old_serving_envelope) = 'object' AND jsonb_typeof(new_prepared_envelope) = 'object'
       AND jsonb_typeof(old_withdrawal_envelope) = 'object' AND jsonb_typeof(new_serving_envelope) = 'object'),
    CHECK (octet_length(old_serving_envelope::text) <= 16384 AND octet_length(new_prepared_envelope::text) <= 16384
       AND octet_length(old_withdrawal_envelope::text) <= 16384 AND octet_length(new_serving_envelope::text) <= 16384),
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
        REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id) ON DELETE CASCADE,
    FOREIGN KEY (old_node_id, org_id, site_id)
        REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT,
    FOREIGN KEY (new_node_id, org_id, site_id)
        REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT
);
CREATE INDEX pool_vip_ownership_handoff_provenance_scope_idx
    ON pool_vip_ownership_handoff_provenance (org_id, site_id, cluster_id, pool_id, operation_id);
-- A pre-issuance claim is one-shot for the exact active generation. This is
-- independent of 0082's later nonterminal-operation index: two concurrent
-- candidates must not both reserve the same owner/generation before P1 emits
-- its durable operation row.
CREATE UNIQUE INDEX pool_vip_ownership_handoff_provenance_one_generation
    ON pool_vip_ownership_handoff_provenance (org_id, pool_id, expected_generation);

-- These child snapshots make the exact capability and UID incarnation inputs
-- durable with the operation. Updating the current P2 caches later cannot
-- change what a restart resolves for this operation.
CREATE TABLE pool_vip_ownership_handoff_provenance_capabilities (
    operation_id    uuid        NOT NULL,
    org_id          uuid        NOT NULL,
    site_id         uuid        NOT NULL,
    cluster_id      uuid        NOT NULL,
    pool_id         uuid        NOT NULL,
    node_id         uuid        NOT NULL,
    wire_version    integer     NOT NULL CHECK (wire_version = 2),
    delivery_row_id uuid        NOT NULL,
    receipt_time    timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    PRIMARY KEY (operation_id, node_id),
    FOREIGN KEY (operation_id, org_id, site_id, cluster_id, pool_id)
        REFERENCES pool_vip_ownership_handoff_provenance (operation_id, org_id, site_id, cluster_id, pool_id) ON DELETE CASCADE,
    FOREIGN KEY (delivery_row_id, org_id)
        REFERENCES pool_vip_ownership_deliveries (id, org_id) ON DELETE RESTRICT
);

CREATE TABLE pool_vip_ownership_handoff_provenance_service_uids (
    operation_id         uuid        NOT NULL,
    org_id               uuid        NOT NULL,
    site_id              uuid        NOT NULL,
    cluster_id           uuid        NOT NULL,
    pool_id              uuid        NOT NULL,
    active_node_id       uuid        NOT NULL,
    promotion_generation bigint     NOT NULL CHECK (promotion_generation > 0),
    namespace            text        NOT NULL CHECK (namespace ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND octet_length(namespace) BETWEEN 1 AND 63),
    service              text        NOT NULL CHECK (service ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND octet_length(service) BETWEEN 1 AND 63),
    service_uid          text        NOT NULL CHECK (octet_length(service_uid) BETWEEN 1 AND 253 AND service_uid !~ '[[:cntrl:]]'),
    observation_revision bigint     NOT NULL CHECK (observation_revision > 0),
    PRIMARY KEY (operation_id, namespace, service, promotion_generation),
    FOREIGN KEY (operation_id, org_id, site_id, cluster_id, pool_id)
        REFERENCES pool_vip_ownership_handoff_provenance (operation_id, org_id, site_id, cluster_id, pool_id) ON DELETE CASCADE
);

CREATE FUNCTION pool_vip_ownership_handoff_provenance_child_immutable() RETURNS trigger AS $$
BEGIN
    -- A crashed leader may refresh only authenticated v2 receipt evidence for
    -- the exact pre-operation claim. An 0082 row closes this narrow reclaim
    -- window; no parent, scope, member, or artifact field can change.
    IF TG_TABLE_NAME = 'pool_vip_ownership_handoff_provenance_capabilities'
       AND current_setting('tunnex.pool_vip_ownership_capability_reclaim', true) = '1'
       AND NEW.operation_id=OLD.operation_id AND NEW.org_id=OLD.org_id
       AND NEW.site_id=OLD.site_id AND NEW.cluster_id=OLD.cluster_id
       AND NEW.pool_id=OLD.pool_id AND NEW.node_id=OLD.node_id
       AND NEW.wire_version=OLD.wire_version
       AND NOT EXISTS (
           SELECT 1 FROM k8s_connector_handoff_operations o
           WHERE o.id=OLD.operation_id AND o.org_id=OLD.org_id
             AND o.site_id=OLD.site_id AND o.pool_id=OLD.pool_id
             AND o.cluster_id=OLD.cluster_id
       ) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'pool VIP ownership handoff provenance child is immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER pool_vip_ownership_handoff_provenance_capabilities_immutable_before_update
    BEFORE UPDATE ON pool_vip_ownership_handoff_provenance_capabilities
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_provenance_child_immutable();
CREATE TRIGGER pool_vip_ownership_handoff_provenance_service_uids_immutable_before_update
    BEFORE UPDATE ON pool_vip_ownership_handoff_provenance_service_uids
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_provenance_child_immutable();

CREATE FUNCTION pool_vip_ownership_handoff_provenance_require_child_scope() RETURNS trigger AS $$
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
              AND d.connector_node_id=NEW.node_id AND d.target_node_id=NEW.node_id AND d.wire_version=2
              AND n.status='active' AND n.revoked_at IS NULL
              AND a.applied_role=d.role
              AND a.applied_manifest_identity=d.manifest_identity
              AND a.applied_promotion_generation=d.promotion_generation
              AND a.applied_manifest_revision=d.manifest_revision
              AND a.owned_route_digest=d.expected_route_digest
              AND a.applied_lease_epoch=CASE WHEN d.role='withdrawal' THEN d.prior_lease_epoch ELSE d.lease_epoch END
              AND ((d.role='serving' AND a.vip_map_digest=d.expected_vip_map_digest)
                   OR (d.role IN ('prepared_non_serving','withdrawal') AND a.vip_map_digest=''))
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
CREATE TRIGGER pool_vip_ownership_handoff_provenance_capabilities_require_scope_before_write
    BEFORE INSERT OR UPDATE ON pool_vip_ownership_handoff_provenance_capabilities
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_provenance_require_child_scope();
CREATE TRIGGER pool_vip_ownership_handoff_provenance_service_uids_require_scope_before_write
    BEFORE INSERT OR UPDATE ON pool_vip_ownership_handoff_provenance_service_uids
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_provenance_require_child_scope();

CREATE FUNCTION pool_vip_ownership_handoff_provenance_require_snapshot() RETURNS trigger AS $$
DECLARE
    snapshot_count integer;
    distinct_count integer;
BEGIN
    SELECT count(*), count(DISTINCT node_id) INTO snapshot_count, distinct_count
    FROM unnest(NEW.membership_snapshot) AS n(node_id);
    IF snapshot_count <> distinct_count OR snapshot_count < 2 THEN
        RAISE EXCEPTION 'pool VIP ownership handoff provenance membership snapshot is invalid';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM k8s_connector_pools p
        WHERE p.id=NEW.pool_id AND p.org_id=NEW.org_id AND p.site_id=NEW.site_id AND p.cluster_id=NEW.cluster_id
          AND p.active_node_id=NEW.old_node_id AND p.generation=NEW.expected_generation
    ) THEN
        RAISE EXCEPTION 'pool VIP ownership handoff provenance does not match active generation';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM k8s_connector_pool_members m
        WHERE m.pool_id=NEW.pool_id AND m.org_id=NEW.org_id AND m.site_id=NEW.site_id AND m.node_id=NEW.old_node_id
    ) OR NOT EXISTS (
        SELECT 1 FROM k8s_connector_pool_members m
        WHERE m.pool_id=NEW.pool_id AND m.org_id=NEW.org_id AND m.site_id=NEW.site_id AND m.node_id=NEW.new_node_id
    ) THEN
        RAISE EXCEPTION 'pool VIP ownership handoff provenance owners are not pool members';
    END IF;
    IF EXISTS (
        SELECT 1 FROM unnest(NEW.membership_snapshot) AS n(node_id)
        LEFT JOIN k8s_connector_pool_members m
          ON m.pool_id=NEW.pool_id AND m.org_id=NEW.org_id AND m.site_id=NEW.site_id AND m.node_id=n.node_id
        WHERE m.node_id IS NULL
    ) OR (SELECT count(*) FROM k8s_connector_pool_members m WHERE m.pool_id=NEW.pool_id AND m.org_id=NEW.org_id AND m.site_id=NEW.site_id) <> snapshot_count THEN
        RAISE EXCEPTION 'pool VIP ownership handoff provenance membership snapshot is stale';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER pool_vip_ownership_handoff_provenance_require_snapshot_before_write
    BEFORE INSERT OR UPDATE OF org_id, site_id, cluster_id, pool_id, old_node_id, new_node_id,
      expected_generation, target_generation, membership_snapshot
    ON pool_vip_ownership_handoff_provenance
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_provenance_require_snapshot();

-- The four opaque JSON bodies remain P2-owned, but their immutable envelope
-- contract has a small relational core.  Enforce that core here as well as in
-- Go so a raw write cannot split an old/new serving snapshot or invent three
-- incompatible target leases. Lease *identities* are CP-issued columns above;
-- no value in an envelope is allowed to mint or replace them.
CREATE FUNCTION pool_vip_ownership_handoff_provenance_require_artifact_contract() RETURNS trigger AS $$
DECLARE
    old_epoch bigint;
    target_epoch bigint;
BEGIN
    IF (NEW.old_serving_envelope->>'role') IS DISTINCT FROM 'serving'
       OR (NEW.new_prepared_envelope->>'role') IS DISTINCT FROM 'prepared_non_serving'
       OR (NEW.old_withdrawal_envelope->>'role') IS DISTINCT FROM 'withdrawal'
       OR (NEW.new_serving_envelope->>'role') IS DISTINCT FROM 'serving'
       OR COALESCE(NEW.old_serving_envelope->>'expected_route_digest', '') !~ '^[0-9a-f]{64}$'
       OR (NEW.old_serving_envelope->>'expected_route_digest') IS NOT DISTINCT FROM '5a5b4496f8450b9f72a61fe951ee55dff755371bdbdb0ed910273674a6ec947d'
       OR COALESCE(NEW.old_serving_envelope->>'expected_vip_map_digest', '') !~ '^[0-9a-f]{64}$'
       OR (NEW.new_serving_envelope->>'expected_route_digest') IS DISTINCT FROM (NEW.old_serving_envelope->>'expected_route_digest')
       OR (NEW.new_serving_envelope->>'expected_vip_map_digest') IS DISTINCT FROM (NEW.old_serving_envelope->>'expected_vip_map_digest')
       OR (NEW.new_prepared_envelope->>'expected_route_digest') IS DISTINCT FROM '5a5b4496f8450b9f72a61fe951ee55dff755371bdbdb0ed910273674a6ec947d'
       OR (NEW.new_prepared_envelope->>'expected_vip_map_digest') IS DISTINCT FROM ''
       OR (NEW.old_withdrawal_envelope->>'expected_route_digest') IS DISTINCT FROM '5a5b4496f8450b9f72a61fe951ee55dff755371bdbdb0ed910273674a6ec947d'
       OR (NEW.old_withdrawal_envelope->>'expected_vip_map_digest') IS DISTINCT FROM ''
       OR COALESCE(NEW.old_serving_envelope->>'lease_epoch', '') !~ '^[1-9][0-9]{0,18}$'
       OR COALESCE(NEW.new_prepared_envelope->>'lease_epoch', '') !~ '^[1-9][0-9]{0,18}$'
       OR COALESCE(NEW.old_withdrawal_envelope->>'lease_epoch', '') !~ '^[1-9][0-9]{0,18}$'
       OR COALESCE(NEW.new_serving_envelope->>'lease_epoch', '') !~ '^[1-9][0-9]{0,18}$'
       OR COALESCE(NEW.old_withdrawal_envelope->>'prior_lease_epoch', '') !~ '^[1-9][0-9]{0,18}$' THEN
        RAISE EXCEPTION 'pool VIP ownership handoff provenance artifact contract is invalid';
    END IF;
    old_epoch := (NEW.old_serving_envelope->>'lease_epoch')::bigint;
    target_epoch := (NEW.new_prepared_envelope->>'lease_epoch')::bigint;
    IF old_epoch >= target_epoch
       OR (NEW.old_withdrawal_envelope->>'prior_lease_epoch')::bigint <> old_epoch
       OR (NEW.old_withdrawal_envelope->>'lease_epoch')::bigint <> target_epoch
       OR (NEW.new_serving_envelope->>'lease_epoch')::bigint <> target_epoch
       OR NEW.new_prepared_expires_at IS DISTINCT FROM NEW.old_withdrawal_expires_at
       OR NEW.new_prepared_expires_at IS DISTINCT FROM NEW.new_serving_expires_at THEN
        RAISE EXCEPTION 'pool VIP ownership handoff provenance target lease is inconsistent';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER pool_vip_ownership_handoff_provenance_require_artifact_contract_before_write
    BEFORE INSERT OR UPDATE OF old_serving_envelope, new_prepared_envelope,
      old_withdrawal_envelope, new_serving_envelope, old_serving_expires_at,
      new_prepared_expires_at, old_withdrawal_expires_at, new_serving_expires_at
    ON pool_vip_ownership_handoff_provenance
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_provenance_require_artifact_contract();

CREATE FUNCTION pool_vip_ownership_handoff_provenance_immutable() RETURNS trigger AS $$
BEGIN
    IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.site_id IS DISTINCT FROM OLD.site_id
       OR NEW.cluster_id IS DISTINCT FROM OLD.cluster_id OR NEW.pool_id IS DISTINCT FROM OLD.pool_id
       OR NEW.old_node_id IS DISTINCT FROM OLD.old_node_id OR NEW.new_node_id IS DISTINCT FROM OLD.new_node_id
       OR NEW.expected_generation IS DISTINCT FROM OLD.expected_generation OR NEW.target_generation IS DISTINCT FROM OLD.target_generation
       OR NEW.decision_transition IS DISTINCT FROM OLD.decision_transition OR NEW.old_lease_identity IS DISTINCT FROM OLD.old_lease_identity
       OR NEW.target_lease_identity IS DISTINCT FROM OLD.target_lease_identity OR NEW.membership_snapshot IS DISTINCT FROM OLD.membership_snapshot
       OR NEW.old_serving_envelope IS DISTINCT FROM OLD.old_serving_envelope OR NEW.new_prepared_envelope IS DISTINCT FROM OLD.new_prepared_envelope
       OR NEW.old_withdrawal_envelope IS DISTINCT FROM OLD.old_withdrawal_envelope OR NEW.new_serving_envelope IS DISTINCT FROM OLD.new_serving_envelope
       OR NEW.old_serving_expires_at IS DISTINCT FROM OLD.old_serving_expires_at OR NEW.new_prepared_expires_at IS DISTINCT FROM OLD.new_prepared_expires_at
       OR NEW.old_withdrawal_expires_at IS DISTINCT FROM OLD.old_withdrawal_expires_at OR NEW.new_serving_expires_at IS DISTINCT FROM OLD.new_serving_expires_at THEN
        RAISE EXCEPTION 'pool VIP ownership handoff provenance is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER pool_vip_ownership_handoff_provenance_immutable_before_update
    BEFORE UPDATE ON pool_vip_ownership_handoff_provenance
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_provenance_immutable();

-- Immutable provenance must not be delete/recreated to bypass replay fences.
-- Cascades from the scoped pool/org/cluster owner remain possible: by the
-- time the dependent delete fires, the exact parent scope no longer exists.
CREATE FUNCTION pool_vip_ownership_handoff_provenance_prevent_direct_delete() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_connector_pools p WHERE p.id=OLD.pool_id AND p.org_id=OLD.org_id AND p.site_id=OLD.site_id AND p.cluster_id=OLD.cluster_id) THEN
        RAISE EXCEPTION 'pool VIP ownership handoff provenance cannot be deleted directly';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER pool_vip_ownership_handoff_provenance_prevent_direct_delete_before_delete
    BEFORE DELETE ON pool_vip_ownership_handoff_provenance
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_provenance_prevent_direct_delete();

CREATE FUNCTION pool_vip_ownership_handoff_provenance_child_prevent_direct_delete() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM pool_vip_ownership_handoff_provenance p WHERE p.operation_id=OLD.operation_id AND p.org_id=OLD.org_id) THEN
        RAISE EXCEPTION 'pool VIP ownership handoff provenance child cannot be deleted directly';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER pool_vip_ownership_handoff_provenance_capabilities_prevent_direct_delete_before_delete
    BEFORE DELETE ON pool_vip_ownership_handoff_provenance_capabilities
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_provenance_child_prevent_direct_delete();
CREATE TRIGGER pool_vip_ownership_handoff_provenance_service_uids_prevent_direct_delete_before_delete
    BEFORE DELETE ON pool_vip_ownership_handoff_provenance_service_uids
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_provenance_child_prevent_direct_delete();

CREATE FUNCTION pool_vip_ownership_handoff_cache_prevent_direct_delete() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_connector_pools p WHERE p.id=OLD.pool_id AND p.org_id=OLD.org_id AND p.site_id=OLD.site_id AND p.cluster_id=OLD.cluster_id) THEN
        RAISE EXCEPTION 'pool VIP ownership handoff cache cannot be deleted directly';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_pool_ownership_v2_capabilities_prevent_direct_delete_before_delete
    BEFORE DELETE ON k8s_pool_ownership_v2_capabilities
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_cache_prevent_direct_delete();
CREATE TRIGGER k8s_pool_service_uid_provenance_prevent_direct_delete_before_delete
    BEFORE DELETE ON k8s_pool_service_uid_provenance
    FOR EACH ROW EXECUTE FUNCTION pool_vip_ownership_handoff_cache_prevent_direct_delete();
