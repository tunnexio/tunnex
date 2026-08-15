-- S10.3c: durable, CP-owned provenance for a single connector-pool handoff.
--
-- This is an expand-only prerequisite for a future scheduler.  It stores no
-- wire payload and grants no serving authority: manifest and lease identity
-- strings are opaque, already-validated P2 prerequisites.  CP receipt times,
-- not agent-supplied clocks, are the only acknowledgement freshness evidence.

-- A handoff CAS audit row must be from the same tenant as the operation.  The
-- audit primary key alone cannot express that relationship, so add the
-- additive composite key before referencing it below.
ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_id_org_key UNIQUE (id, org_id);

CREATE TABLE k8s_connector_handoff_operations (
    id                                  uuid PRIMARY KEY,
    org_id                              uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id                             uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    pool_id                             uuid NOT NULL,
    cluster_id                          uuid NOT NULL,

    -- Immutable old/new pool state. target_generation is exactly the single
    -- promotion increment that the later CAS must apply.
    old_node_id                         uuid NOT NULL,
    new_node_id                         uuid NOT NULL,
    expected_generation                 bigint NOT NULL CHECK (expected_generation > 0),
    target_generation                   bigint NOT NULL CHECK (target_generation = expected_generation + 1),

    -- Opaque bounded references to CP-validated P2 artifacts and leases.
    -- They are identifiers/provenance, never agent-authenticated assertions.
    old_serving_manifest_identity       text NOT NULL CHECK (octet_length(old_serving_manifest_identity) BETWEEN 1 AND 512 AND btrim(old_serving_manifest_identity) <> ''),
    candidate_prepared_manifest_identity text NOT NULL CHECK (octet_length(candidate_prepared_manifest_identity) BETWEEN 1 AND 512 AND btrim(candidate_prepared_manifest_identity) <> ''),
    old_withdrawal_manifest_identity    text NOT NULL CHECK (octet_length(old_withdrawal_manifest_identity) BETWEEN 1 AND 512 AND btrim(old_withdrawal_manifest_identity) <> ''),
    new_serving_manifest_identity       text NOT NULL CHECK (octet_length(new_serving_manifest_identity) BETWEEN 1 AND 512 AND btrim(new_serving_manifest_identity) <> ''),
    -- A resume must retain the exact validated artifact identity, including
    -- its monotonic revision.  Identities alone are opaque and cannot safely
    -- reconstruct an ArtifactPrerequisite after a coordinator restart.
    old_serving_manifest_revision       bigint NOT NULL CHECK (old_serving_manifest_revision > 0),
    candidate_prepared_manifest_revision bigint NOT NULL CHECK (candidate_prepared_manifest_revision > 0),
    old_withdrawal_manifest_revision    bigint NOT NULL CHECK (old_withdrawal_manifest_revision > 0),
    new_serving_manifest_revision       bigint NOT NULL CHECK (new_serving_manifest_revision > 0),
    -- The exact P2 route/VIP digests are immutable artifact prerequisites,
    -- not derivable from the opaque manifest identity. Persist every role's
    -- validated values so crash/restart reconstruction cannot synthesize or
    -- silently drop serving authority.
    old_serving_expected_route_digest       text NOT NULL CHECK (old_serving_expected_route_digest ~ '^[0-9a-f]{64}$' AND old_serving_expected_route_digest <> '5a5b4496f8450b9f72a61fe951ee55dff755371bdbdb0ed910273674a6ec947d'),
    old_serving_expected_vip_map_digest     text NOT NULL CHECK (old_serving_expected_vip_map_digest ~ '^[0-9a-f]{64}$'),
    candidate_prepared_expected_route_digest text NOT NULL CHECK (candidate_prepared_expected_route_digest = '5a5b4496f8450b9f72a61fe951ee55dff755371bdbdb0ed910273674a6ec947d'),
    candidate_prepared_expected_vip_map_digest text NOT NULL CHECK (candidate_prepared_expected_vip_map_digest = ''),
    old_withdrawal_expected_route_digest    text NOT NULL CHECK (old_withdrawal_expected_route_digest = '5a5b4496f8450b9f72a61fe951ee55dff755371bdbdb0ed910273674a6ec947d'),
    old_withdrawal_expected_vip_map_digest  text NOT NULL CHECK (old_withdrawal_expected_vip_map_digest = ''),
    new_serving_expected_route_digest       text NOT NULL CHECK (new_serving_expected_route_digest ~ '^[0-9a-f]{64}$' AND new_serving_expected_route_digest <> '5a5b4496f8450b9f72a61fe951ee55dff755371bdbdb0ed910273674a6ec947d'),
    new_serving_expected_vip_map_digest     text NOT NULL CHECK (new_serving_expected_vip_map_digest ~ '^[0-9a-f]{64}$'),
    old_lease_identity                  text NOT NULL CHECK (octet_length(old_lease_identity) BETWEEN 1 AND 512 AND btrim(old_lease_identity) <> ''),
    target_lease_identity               text NOT NULL CHECK (octet_length(target_lease_identity) BETWEEN 1 AND 512 AND btrim(target_lease_identity) <> ''),
    old_lease_epoch                     bigint NOT NULL CHECK (old_lease_epoch > 0),
    target_lease_epoch                  bigint NOT NULL CHECK (target_lease_epoch > old_lease_epoch),
    old_lease_expires_at                timestamptz NOT NULL,
    target_lease_expires_at             timestamptz NOT NULL,
    -- Null is the mixed-version/legacy compatibility state. A non-null value
    -- is the exact 0083 membership incarnation that made this handoff
    -- eligible; 0083 terminally aborts only pre-CAS operation phases on
    -- membership churn, while post-CAS generation/lease-fenced completion
    -- continues so the committed active owner is not stranded non-serving.
    observed_membership_epoch           bigint CHECK (observed_membership_epoch >= 0),

    -- The pure health decision is immutable operation provenance.  It is not
    -- inferred from later preferred-node edits when a durable operation is
    -- resumed; doing so could relabel a promotion as a failback.
    decision_transition                 text NOT NULL CHECK (decision_transition IN ('promoted', 'failed_back')),

    -- Roles are explicit because a prepared artifact may not accept traffic.
    old_serving_role                    text NOT NULL DEFAULT 'serving' CHECK (old_serving_role = 'serving'),
    candidate_prepared_role             text NOT NULL DEFAULT 'prepared_non_serving' CHECK (candidate_prepared_role = 'prepared_non_serving'),
    old_withdrawal_role                 text NOT NULL DEFAULT 'prepared_non_serving' CHECK (old_withdrawal_role = 'prepared_non_serving'),
    new_serving_role                    text NOT NULL DEFAULT 'serving' CHECK (new_serving_role = 'serving'),

    phase                               text NOT NULL DEFAULT 'prepare_candidate'
                                        CHECK (phase IN ('prepare_candidate', 'await_prepared_ack', 'await_withdrawal', 'cas_active', 'enable_serving', 'await_serving_ack', 'finalize', 'complete', 'failed')),
    prepared_ack_received_at            timestamptz,
    withdrawal_ack_received_at          timestamptz,
    withdrawal_expiry_received_at       timestamptz,
    serving_ack_received_at             timestamptz,

    -- These three values are written together only by the atomic CAS CTE.
    cas_receipt_at                      timestamptz,
    cas_audit_id                        uuid,
    cas_audit_applied                   boolean NOT NULL DEFAULT false,
    failure_reason                      text CHECK (failure_reason IS NULL OR (octet_length(failure_reason) BETWEEN 1 AND 512 AND btrim(failure_reason) <> '')),
    created_at                          timestamptz NOT NULL DEFAULT now(),
    updated_at                          timestamptz NOT NULL DEFAULT now(),

    CHECK (old_node_id <> new_node_id),
    -- Serving may move owners only as one exact P2 snapshot; P1 never
    -- reconstructs a new owner from a different route/VIP digest after CAS.
    CHECK (old_serving_expected_route_digest = new_serving_expected_route_digest
       AND old_serving_expected_vip_map_digest = new_serving_expected_vip_map_digest),
    CHECK (withdrawal_ack_received_at IS NULL OR withdrawal_expiry_received_at IS NULL),
    CHECK (
        (cas_audit_applied AND cas_receipt_at IS NOT NULL AND cas_audit_id IS NOT NULL)
        OR
        (NOT cas_audit_applied AND cas_receipt_at IS NULL AND cas_audit_id IS NULL)
    ),
    CHECK (
        (phase = 'failed' AND failure_reason IS NOT NULL)
        OR
        (phase <> 'failed' AND failure_reason IS NULL)
    ),
    CHECK (
        phase = 'failed'
        OR (phase IN ('prepare_candidate', 'await_prepared_ack')
            AND prepared_ack_received_at IS NULL
            AND withdrawal_ack_received_at IS NULL
            AND withdrawal_expiry_received_at IS NULL
            AND serving_ack_received_at IS NULL
            AND NOT cas_audit_applied)
        OR (phase = 'await_withdrawal'
            AND prepared_ack_received_at IS NOT NULL
            AND withdrawal_ack_received_at IS NULL
            AND withdrawal_expiry_received_at IS NULL
            AND serving_ack_received_at IS NULL
            AND NOT cas_audit_applied)
        OR (phase = 'cas_active'
            AND prepared_ack_received_at IS NOT NULL
            AND (withdrawal_ack_received_at IS NOT NULL OR withdrawal_expiry_received_at IS NOT NULL)
            AND serving_ack_received_at IS NULL
            AND NOT cas_audit_applied)
        OR (phase IN ('enable_serving', 'await_serving_ack')
            AND prepared_ack_received_at IS NOT NULL
            AND (withdrawal_ack_received_at IS NOT NULL OR withdrawal_expiry_received_at IS NOT NULL)
            AND serving_ack_received_at IS NULL
            AND cas_audit_applied)
        OR (phase IN ('finalize', 'complete')
            AND prepared_ack_received_at IS NOT NULL
            AND (withdrawal_ack_received_at IS NOT NULL OR withdrawal_expiry_received_at IS NOT NULL)
            AND serving_ack_received_at IS NOT NULL
            AND cas_audit_applied)
    ),

    -- The pool relationship is exact: a raw writer cannot attach this
    -- operation to another cluster in the same org/site.
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
        REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id)
        ON DELETE CASCADE,
    -- Both immutable owners must remain members of this exact pool.
    FOREIGN KEY (pool_id, org_id, site_id, old_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (pool_id, org_id, site_id, new_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (cas_audit_id, org_id)
        REFERENCES audit_logs (id, org_id)
        ON DELETE RESTRICT,
    UNIQUE (cas_audit_id)
);

-- A pool may have historical terminal records, but only one uncompleted or
-- nonterminal operation. This makes create/resume deterministic.
CREATE UNIQUE INDEX k8s_connector_handoff_operations_one_nonterminal_pool
    ON k8s_connector_handoff_operations (pool_id)
    WHERE phase NOT IN ('complete', 'failed');
CREATE INDEX k8s_connector_handoff_operations_org_site_pool_idx
    ON k8s_connector_handoff_operations (org_id, site_id, pool_id);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_connector_handoff_operations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The operation intent is write-once. Only receipt/progress data may change;
-- terminal phase transitions are one-way, so raw writes cannot replay a stale
-- delivery or reopen a completed/failed handoff.
CREATE OR REPLACE FUNCTION k8s_connector_handoff_operations_enforce_update()
RETURNS trigger AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.org_id IS DISTINCT FROM OLD.org_id
       OR NEW.site_id IS DISTINCT FROM OLD.site_id
       OR NEW.pool_id IS DISTINCT FROM OLD.pool_id
       OR NEW.cluster_id IS DISTINCT FROM OLD.cluster_id
       OR NEW.old_node_id IS DISTINCT FROM OLD.old_node_id
       OR NEW.new_node_id IS DISTINCT FROM OLD.new_node_id
       OR NEW.expected_generation IS DISTINCT FROM OLD.expected_generation
       OR NEW.target_generation IS DISTINCT FROM OLD.target_generation
       OR NEW.old_serving_manifest_identity IS DISTINCT FROM OLD.old_serving_manifest_identity
       OR NEW.candidate_prepared_manifest_identity IS DISTINCT FROM OLD.candidate_prepared_manifest_identity
       OR NEW.old_withdrawal_manifest_identity IS DISTINCT FROM OLD.old_withdrawal_manifest_identity
       OR NEW.new_serving_manifest_identity IS DISTINCT FROM OLD.new_serving_manifest_identity
       OR NEW.old_serving_manifest_revision IS DISTINCT FROM OLD.old_serving_manifest_revision
       OR NEW.candidate_prepared_manifest_revision IS DISTINCT FROM OLD.candidate_prepared_manifest_revision
       OR NEW.old_withdrawal_manifest_revision IS DISTINCT FROM OLD.old_withdrawal_manifest_revision
       OR NEW.new_serving_manifest_revision IS DISTINCT FROM OLD.new_serving_manifest_revision
       OR NEW.old_serving_expected_route_digest IS DISTINCT FROM OLD.old_serving_expected_route_digest
       OR NEW.old_serving_expected_vip_map_digest IS DISTINCT FROM OLD.old_serving_expected_vip_map_digest
       OR NEW.candidate_prepared_expected_route_digest IS DISTINCT FROM OLD.candidate_prepared_expected_route_digest
       OR NEW.candidate_prepared_expected_vip_map_digest IS DISTINCT FROM OLD.candidate_prepared_expected_vip_map_digest
       OR NEW.old_withdrawal_expected_route_digest IS DISTINCT FROM OLD.old_withdrawal_expected_route_digest
       OR NEW.old_withdrawal_expected_vip_map_digest IS DISTINCT FROM OLD.old_withdrawal_expected_vip_map_digest
       OR NEW.new_serving_expected_route_digest IS DISTINCT FROM OLD.new_serving_expected_route_digest
       OR NEW.new_serving_expected_vip_map_digest IS DISTINCT FROM OLD.new_serving_expected_vip_map_digest
       OR NEW.old_lease_identity IS DISTINCT FROM OLD.old_lease_identity
       OR NEW.target_lease_identity IS DISTINCT FROM OLD.target_lease_identity
       OR NEW.old_lease_epoch IS DISTINCT FROM OLD.old_lease_epoch
       OR NEW.target_lease_epoch IS DISTINCT FROM OLD.target_lease_epoch
       OR NEW.old_lease_expires_at IS DISTINCT FROM OLD.old_lease_expires_at
       OR NEW.target_lease_expires_at IS DISTINCT FROM OLD.target_lease_expires_at

       OR NEW.observed_membership_epoch IS DISTINCT FROM OLD.observed_membership_epoch
       OR NEW.decision_transition IS DISTINCT FROM OLD.decision_transition
       OR NEW.old_serving_role IS DISTINCT FROM OLD.old_serving_role
       OR NEW.candidate_prepared_role IS DISTINCT FROM OLD.candidate_prepared_role
       OR NEW.old_withdrawal_role IS DISTINCT FROM OLD.old_withdrawal_role
       OR NEW.new_serving_role IS DISTINCT FROM OLD.new_serving_role THEN
        RAISE EXCEPTION 'k8s connector handoff operation intent is immutable';
    END IF;

    IF NEW.phase <> OLD.phase AND NOT (
        (OLD.phase = 'prepare_candidate' AND NEW.phase = 'await_prepared_ack')
        OR (OLD.phase = 'await_prepared_ack' AND NEW.phase = 'await_withdrawal')
        OR (OLD.phase = 'await_withdrawal' AND NEW.phase = 'cas_active')
        OR (OLD.phase = 'cas_active' AND NEW.phase = 'enable_serving')
        OR (OLD.phase = 'enable_serving' AND NEW.phase = 'await_serving_ack')
        OR (OLD.phase = 'await_serving_ack' AND NEW.phase = 'finalize')
        OR (OLD.phase = 'finalize' AND NEW.phase = 'complete')
        OR (OLD.phase NOT IN ('complete', 'failed') AND NEW.phase = 'failed')
    ) THEN
        RAISE EXCEPTION 'k8s connector handoff operation phase cannot move from % to %', OLD.phase, NEW.phase;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_connector_handoff_operations_enforce_update
    BEFORE UPDATE ON k8s_connector_handoff_operations
    FOR EACH ROW EXECUTE FUNCTION k8s_connector_handoff_operations_enforce_update();
