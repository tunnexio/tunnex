-- S10.3 P2: durable, mTLS-scoped ownership-delivery envelopes. The HTTP
-- channel owns no ledger: these tables preserve issued v1 envelopes, one
-- monotonic fence per handoff scope, and exact acknowledgement retries across
-- API restart/HA failover. No scheduler or serving transition is introduced.

-- Consolidation order is P1 0079 connector pools, P2 0080 Service-port
-- exposures, this P2 0081 delivery ledger, then P1 0082 handoff operations.
-- P1 0079 supplies the exact composite pool and member keys below. Binding
-- both envelope nodes through that membership makes org/site/cluster/pool
-- scope database-enforced rather than a store-only convention.

CREATE TABLE pool_vip_ownership_delivery_states (
    id                   uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id               uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id              uuid        NOT NULL,
    cluster_id           uuid        NOT NULL,
    pool_id              uuid        NOT NULL,
    connector_node_id    uuid        NOT NULL,
    scope_identity       text        NOT NULL,
    promotion_generation bigint      NOT NULL DEFAULT 0 CHECK (promotion_generation >= 0),
    manifest_revision    bigint      NOT NULL DEFAULT 0 CHECK (manifest_revision >= 0),
    lease_epoch          bigint      NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, site_id, cluster_id, pool_id, connector_node_id),
    UNIQUE (id, org_id),
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
        REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id) ON DELETE CASCADE,
    FOREIGN KEY (pool_id, org_id, site_id, connector_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id) ON DELETE RESTRICT
);
CREATE INDEX pool_vip_ownership_delivery_states_org_idx
    ON pool_vip_ownership_delivery_states (org_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON pool_vip_ownership_delivery_states
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE pool_vip_ownership_deliveries (
    id                   uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id               uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id              uuid        NOT NULL,
    cluster_id           uuid        NOT NULL,
    pool_id              uuid        NOT NULL,
    connector_node_id    uuid        NOT NULL,
    target_node_id       uuid        NOT NULL,
    operation_id         uuid        NOT NULL,
    wire_version         integer     NOT NULL CHECK (wire_version IN (1, 2)),
    manifest_identity    text        NOT NULL,
    role                 text        NOT NULL CHECK (role IN ('prepared_non_serving', 'serving', 'withdrawal')),
    promotion_generation bigint      NOT NULL CHECK (promotion_generation > 0),
    manifest_revision    bigint      NOT NULL CHECK (manifest_revision > 0),
    lease_epoch          bigint      NOT NULL CHECK (lease_epoch > 0),
    delivery_phase       text        NOT NULL CHECK (delivery_phase IN ('prepare', 'serve', 'withdraw')),
    delivery_id          uuid        NOT NULL,
    delivery_nonce       text        NOT NULL,
    owned_routes         jsonb       NOT NULL DEFAULT '[]'::jsonb,
    expected_route_digest text       NOT NULL DEFAULT '',
    expected_vip_map_digest text     NOT NULL DEFAULT '',
    prior_lease_epoch    bigint      NOT NULL DEFAULT 0 CHECK (prior_lease_epoch >= 0),
    expires_at           timestamptz NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, delivery_id),
    UNIQUE (id, org_id),
    CHECK (
        (wire_version = 1 AND owned_routes = '[]'::jsonb
         AND expected_route_digest = '' AND expected_vip_map_digest = '' AND prior_lease_epoch = 0)
        OR
        (wire_version = 2 AND jsonb_typeof(owned_routes) = 'array'
         AND expected_route_digest ~ '^[0-9a-f]{64}$'
         AND (expected_vip_map_digest = '' OR expected_vip_map_digest ~ '^[0-9a-f]{64}$'))
    ),
    -- Mirrors the v2 validator's 512 canonical-IPv4 route ceiling and keeps
    -- raw SQL rows below the existing 16 KiB ownership JSON frame. Without
    -- this, a malformed durable JSONB row could force unbounded unmarshal on
    -- later polling/readback before code validation runs.
    CHECK (
        jsonb_typeof(owned_routes) = 'array'
        AND jsonb_array_length(owned_routes) <= 512
        AND octet_length(owned_routes::text) <= 12288
    ),
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
        REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id) ON DELETE CASCADE,
    FOREIGN KEY (pool_id, org_id, site_id, connector_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id) ON DELETE RESTRICT,
    FOREIGN KEY (pool_id, org_id, site_id, target_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id) ON DELETE RESTRICT
);
CREATE INDEX pool_vip_ownership_deliveries_target_idx
    ON pool_vip_ownership_deliveries (org_id, target_node_id, expires_at, manifest_revision DESC, created_at DESC);
CREATE INDEX pool_vip_ownership_deliveries_scope_idx
    ON pool_vip_ownership_deliveries (org_id, site_id, cluster_id, pool_id, connector_node_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON pool_vip_ownership_deliveries
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE pool_vip_ownership_delivery_ack_receipts (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id          uuid        NOT NULL,
    delivery_row_id uuid        NOT NULL,
    state_id        uuid        NOT NULL,
    fingerprint     text        NOT NULL,
    receipt_time    timestamptz NOT NULL,
    applied_role                text,
    applied_manifest_identity   text,
    applied_promotion_generation bigint,
    applied_manifest_revision   bigint,
    applied_lease_epoch         bigint,
    owned_route_digest          text,
    vip_map_digest              text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (delivery_row_id),
    FOREIGN KEY (delivery_row_id, org_id)
        REFERENCES pool_vip_ownership_deliveries (id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (state_id, org_id)
        REFERENCES pool_vip_ownership_delivery_states (id, org_id) ON DELETE RESTRICT,
    CHECK (
        (applied_role IS NULL AND applied_manifest_identity IS NULL
         AND applied_promotion_generation IS NULL AND applied_manifest_revision IS NULL
         AND applied_lease_epoch IS NULL AND owned_route_digest IS NULL AND vip_map_digest IS NULL)
        OR
        (applied_role IN ('prepared_non_serving', 'serving', 'withdrawal')
         AND applied_manifest_identity ~ '^[0-9a-f]{64}$'
         AND applied_promotion_generation > 0 AND applied_manifest_revision > 0
         AND applied_lease_epoch > 0 AND owned_route_digest ~ '^[0-9a-f]{64}$'
         AND (vip_map_digest = '' OR vip_map_digest ~ '^[0-9a-f]{64}$'))
    )
);
CREATE INDEX pool_vip_ownership_delivery_ack_receipts_org_idx
    ON pool_vip_ownership_delivery_ack_receipts (org_id, state_id);
