-- S10.3c: durable CP-owned observations for connector-pool hysteresis.
-- A state row is exact to one cluster-owned pool; candidate streak rows are
-- exact to both that state and current pool membership. This is health
-- history only: it does not authorize a handoff, change pool ownership, or
-- persist agent claims as CP provenance.
CREATE TABLE k8s_connector_pool_health_states (
    id                          uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id                      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id                     uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    cluster_id                  uuid NOT NULL,
    pool_id                     uuid NOT NULL,
    -- Incremented synchronously by pool-member membership/priority changes.
    -- It is a durable membership incarnation, not agent-provided evidence.
    membership_epoch            bigint NOT NULL DEFAULT 0 CHECK (membership_epoch >= 0),
    observed_active_node_id     uuid NOT NULL,
    observed_generation         bigint NOT NULL CHECK (observed_generation > 0),
    stale_ticks                 integer NOT NULL DEFAULT 0 CHECK (stale_ticks >= 0),
    preferred_fresh_ticks       integer NOT NULL DEFAULT 0 CHECK (preferred_fresh_ticks >= 0),
    last_transition             text NOT NULL DEFAULT 'no_change'
                                CHECK (last_transition IN ('no_change', 'promoted', 'failed_back', 'needs_attention')),
    last_transition_from_node_id uuid,
    last_transition_to_node_id   uuid,
    last_observation_key        text,
    last_observation_at         timestamptz,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (pool_id),
    UNIQUE (id, org_id, site_id, cluster_id, pool_id),
    UNIQUE (pool_id, org_id, site_id, cluster_id),
    CHECK (
        (last_observation_key IS NULL AND last_observation_at IS NULL)
        OR (
            last_observation_key ~ '^[0-9a-f]{64}$'
            AND last_observation_at IS NOT NULL
        )
    ),
    CHECK (
        (last_transition IN ('promoted', 'failed_back') AND last_transition_from_node_id IS NOT NULL AND last_transition_to_node_id IS NOT NULL)
        OR (last_transition NOT IN ('promoted', 'failed_back') AND last_transition_from_node_id IS NULL AND last_transition_to_node_id IS NULL)
    ),
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
        REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id)
        ON DELETE CASCADE
);

CREATE INDEX k8s_connector_pool_health_states_org_site_pool_idx
    ON k8s_connector_pool_health_states (org_id, site_id, pool_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_connector_pool_health_states
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE k8s_connector_pool_health_candidate_ticks (
    state_id                    uuid NOT NULL,
    org_id                      uuid NOT NULL,
    site_id                     uuid NOT NULL,
    cluster_id                  uuid NOT NULL,
    pool_id                     uuid NOT NULL,
    node_id                     uuid NOT NULL,
    healthy_ticks               integer NOT NULL DEFAULT 0 CHECK (healthy_ticks >= 0),
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (state_id, node_id),
    UNIQUE (state_id, org_id, site_id, cluster_id, pool_id, node_id),
    FOREIGN KEY (state_id, org_id, site_id, cluster_id, pool_id)
        REFERENCES k8s_connector_pool_health_states (id, org_id, site_id, cluster_id, pool_id)
        ON DELETE CASCADE,
    -- A departed member loses its streak atomically with the membership row;
    -- a later member can never inherit a prior pool's readiness evidence. It
    -- is deferred so a raw cross-pool move reaches the AFTER trigger, which
    -- deletes the old tick and invalidates both pool incarnations before commit.
    FOREIGN KEY (pool_id, org_id, site_id, node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX k8s_connector_pool_health_candidate_ticks_org_site_pool_idx
    ON k8s_connector_pool_health_candidate_ticks (org_id, site_id, pool_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_connector_pool_health_candidate_ticks
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A retained threshold is valid only for one exact pool-membership
-- incarnation. This trigger fires even when no observer runs between a member
-- leaving and the same UUID returning, so no old pending transition can be
-- resurrected. Priority changes are included because deterministic candidate
-- selection depends on them.
CREATE OR REPLACE FUNCTION k8s_connector_pool_health_membership_changed()
RETURNS trigger AS $$
DECLARE
    old_pool_id uuid;
    new_pool_id uuid;
BEGIN
    IF TG_OP = 'UPDATE' AND NOT (
        OLD.pool_id IS DISTINCT FROM NEW.pool_id
        OR OLD.org_id IS DISTINCT FROM NEW.org_id
        OR OLD.site_id IS DISTINCT FROM NEW.site_id
        OR OLD.node_id IS DISTINCT FROM NEW.node_id
        OR OLD.admin_priority IS DISTINCT FROM NEW.admin_priority
    ) THEN
        RETURN NULL;
    END IF;

    IF TG_OP <> 'INSERT' THEN
        old_pool_id := OLD.pool_id;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_pool_id := NEW.pool_id;
    END IF;

    -- A raw membership move can affect two pools. Lock both durable state rows
    -- by UUID before clearing either, so opposite-direction moves take the same
    -- lock order and cannot deadlock each other.
    PERFORM 1
    FROM k8s_connector_pool_health_states s
    WHERE s.pool_id = old_pool_id OR s.pool_id = new_pool_id
    ORDER BY s.pool_id
    FOR UPDATE;

    DELETE FROM k8s_connector_pool_health_candidate_ticks t
    USING k8s_connector_pool_health_states s
    WHERE t.state_id = s.id
      AND (s.pool_id = old_pool_id OR s.pool_id = new_pool_id);

    UPDATE k8s_connector_pool_health_states
    SET membership_epoch = membership_epoch + 1,
        stale_ticks = 0,
        preferred_fresh_ticks = 0,
        last_transition = 'no_change',
        last_transition_from_node_id = NULL,
        last_transition_to_node_id = NULL,
        last_observation_key = NULL,
        last_observation_at = NULL,
        updated_at = now()
    WHERE pool_id = old_pool_id OR pool_id = new_pool_id;

    -- An epoch-bound operation selected from the membership incarnation just
    -- invalidated above must never deliver another artifact or reach the pool
    -- CAS while ownership is still old. Once the atomic CAS has moved ownership
    -- to new, this trigger only clears health history: generation- and
    -- lease-fenced enable/ack/finalize must finish so the active owner cannot
    -- be stranded non-serving. The old/new member rows themselves are already
    -- protected by the operation's exact membership FKs. Terminal and legacy
    -- (null epoch) rows remain untouched for compatibility/history.
    UPDATE k8s_connector_handoff_operations o
    SET phase = 'failed',
        failure_reason = 'membership_epoch_changed',
        updated_at = now()
    FROM k8s_connector_pool_health_states s
    WHERE (s.pool_id = old_pool_id OR s.pool_id = new_pool_id)
      AND o.pool_id = s.pool_id
      AND o.org_id = s.org_id
      AND o.site_id = s.site_id
      AND o.cluster_id = s.cluster_id
      AND o.observed_membership_epoch IS NOT NULL
      AND o.observed_membership_epoch <> s.membership_epoch
      AND o.phase IN ('prepare_candidate', 'await_prepared_ack', 'await_withdrawal', 'cas_active');
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_connector_pool_health_membership_inserted
AFTER INSERT
ON k8s_connector_pool_members
FOR EACH ROW EXECUTE FUNCTION k8s_connector_pool_health_membership_changed();

CREATE TRIGGER k8s_connector_pool_health_membership_deleted
AFTER DELETE
ON k8s_connector_pool_members
FOR EACH ROW EXECUTE FUNCTION k8s_connector_pool_health_membership_changed();

CREATE TRIGGER k8s_connector_pool_health_membership_updated
AFTER UPDATE OF pool_id, org_id, site_id, node_id, admin_priority
ON k8s_connector_pool_members
FOR EACH ROW
WHEN (
    OLD.pool_id IS DISTINCT FROM NEW.pool_id
    OR OLD.org_id IS DISTINCT FROM NEW.org_id
    OR OLD.site_id IS DISTINCT FROM NEW.site_id
    OR OLD.node_id IS DISTINCT FROM NEW.node_id
    OR OLD.admin_priority IS DISTINCT FROM NEW.admin_priority
)
EXECUTE FUNCTION k8s_connector_pool_health_membership_changed();

-- Preferred identity, active ownership, and generation are also part of the
-- pure pool input. They invalidate counters/retained decisions immediately;
-- only membership mutations increment membership_epoch.
CREATE OR REPLACE FUNCTION k8s_connector_pool_health_pool_changed()
RETURNS trigger AS $$
BEGIN
    IF NOT (
        OLD.preferred_node_id IS DISTINCT FROM NEW.preferred_node_id
        OR OLD.active_node_id IS DISTINCT FROM NEW.active_node_id
        OR OLD.generation IS DISTINCT FROM NEW.generation
    ) THEN
        RETURN NULL;
    END IF;

    DELETE FROM k8s_connector_pool_health_candidate_ticks t
    USING k8s_connector_pool_health_states s
    WHERE t.state_id = s.id AND s.pool_id = NEW.id;

    UPDATE k8s_connector_pool_health_states
    SET stale_ticks = 0,
        preferred_fresh_ticks = 0,
        last_transition = 'no_change',
        last_transition_from_node_id = NULL,
        last_transition_to_node_id = NULL,
        last_observation_key = NULL,
        last_observation_at = NULL,
        updated_at = now()
    WHERE pool_id = NEW.id;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_connector_pool_health_pool_changed
AFTER UPDATE OF preferred_node_id, active_node_id, generation
ON k8s_connector_pools
FOR EACH ROW
WHEN (
    OLD.preferred_node_id IS DISTINCT FROM NEW.preferred_node_id
    OR OLD.active_node_id IS DISTINCT FROM NEW.active_node_id
    OR OLD.generation IS DISTINCT FROM NEW.generation
)
EXECUTE FUNCTION k8s_connector_pool_health_pool_changed();
