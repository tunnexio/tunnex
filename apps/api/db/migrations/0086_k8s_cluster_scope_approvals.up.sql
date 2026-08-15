-- S10.3 P3: approval-gated dynamic Kubernetes cluster scopes.  This migration
-- follows the consolidated P1/P2 0079–0085 chain: 0080 supplies exact-port
-- children and 0084 supplies the authoritative Kubernetes Service UID ledger.
-- It intentionally grants no namespace, Pod, Node, VPC, or Kubernetes API
-- entitlement.  A scope is a policy destination whose members are individual
-- exact-port Service children only.

ALTER TABLE policy_rules ADD COLUMN dst_k8s_cluster_id uuid;

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource', 'group', 'site', 'k8s_service', 'k8s_cluster_scope'));
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind = 'resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind = 'group' AND dst_group_id IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind = 'site' AND dst_site_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_k8s_service_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind = 'k8s_service' AND dst_k8s_service_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_cluster_id IS NULL)
 OR (dst_kind = 'k8s_cluster_scope' AND dst_k8s_cluster_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
);

CREATE INDEX policy_rules_k8s_cluster_scope_idx
    ON policy_rules (org_id, dst_k8s_cluster_id)
    WHERE dst_kind = 'k8s_cluster_scope';
-- A source may own at most one scope for one exact cluster. These partial
-- indexes are the concurrency backstop for lost create retries; memberships
-- remain the explicit bounded child queue below.
CREATE UNIQUE INDEX policy_rules_group_k8s_cluster_scope_uniq
    ON policy_rules (org_id, src_group_id, dst_k8s_cluster_id)
    WHERE src_kind = 'group' AND dst_kind = 'k8s_cluster_scope';
CREATE UNIQUE INDEX policy_rules_user_k8s_cluster_scope_uniq
    ON policy_rules (org_id, src_user_id, dst_k8s_cluster_id)
    WHERE src_kind = 'user' AND dst_kind = 'k8s_cluster_scope';
CREATE UNIQUE INDEX policy_rules_site_k8s_cluster_scope_uniq
    ON policy_rules (org_id, src_site_id, dst_k8s_cluster_id)
    WHERE src_kind = 'site' AND dst_kind = 'k8s_cluster_scope';
CREATE UNIQUE INDEX policy_rules_cidr_k8s_cluster_scope_uniq
    ON policy_rules (org_id, src_cidr, dst_k8s_cluster_id)
    WHERE src_kind = 'cidr' AND dst_kind = 'k8s_cluster_scope';
CREATE UNIQUE INDEX policy_rules_agent_k8s_cluster_scope_uniq
    ON policy_rules (org_id, src_device_id, dst_k8s_cluster_id)
    WHERE src_kind = 'agent' AND dst_kind = 'k8s_cluster_scope';

-- One row is the durable scope and its pending queue.  The rule is created in
-- the same transaction as its selected initial memberships.  `active` keeps a
-- later disable/delete implementation from reusing membership history.
CREATE TABLE k8s_cluster_scope_grants (
    rule_id                 uuid        PRIMARY KEY REFERENCES policy_rules (id) ON DELETE CASCADE,
    org_id                  uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    cluster_id              uuid        NOT NULL REFERENCES k8s_clusters (id) ON DELETE CASCADE,
    created_by_user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    initial_candidate_count integer     NOT NULL CHECK (initial_candidate_count BETWEEN 0 AND 100),
    active                  boolean     NOT NULL DEFAULT true,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (rule_id, org_id, cluster_id)
);
CREATE INDEX k8s_cluster_scope_grants_cluster_active_idx
    ON k8s_cluster_scope_grants (org_id, cluster_id)
    WHERE active;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_cluster_scope_grants
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A raw SQL writer cannot attach an arbitrary policy rule to a scope. The
-- destination arm and organization are one identity, not merely values the API
-- happened to validate before calling INSERT.
CREATE FUNCTION k8s_cluster_scope_grant_require_rule() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM policy_rules r
        WHERE r.id = NEW.rule_id AND r.org_id = NEW.org_id
          AND r.dst_kind = 'k8s_cluster_scope'
          AND r.dst_k8s_cluster_id = NEW.cluster_id
    ) OR NOT EXISTS (
        SELECT 1 FROM k8s_clusters c
        WHERE c.id = NEW.cluster_id AND c.org_id = NEW.org_id
    ) THEN
        RAISE EXCEPTION 'k8s cluster scope rule does not own the stated org and cluster';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_cluster_scope_grants_require_rule_before_write
    BEFORE INSERT OR UPDATE OF rule_id, org_id, cluster_id ON k8s_cluster_scope_grants
    FOR EACH ROW EXECUTE FUNCTION k8s_cluster_scope_grant_require_rule();

-- Scope actor fields are audit provenance, but users are global. Validate the
-- actor against the stated tenant at the write boundary rather than using a
-- composite FK: a later membership removal must not erase an already-valid
-- historical scope creation or decision. HTTP RBAC remains responsible for
-- requiring a human Owner/Admin; this trigger makes that proven actor tenant
-- scoped for raw SQL writers as well.
CREATE FUNCTION k8s_cluster_scope_actor_require_org_membership() RETURNS trigger AS $$
DECLARE
    actor uuid;
BEGIN
    IF TG_TABLE_NAME = 'k8s_cluster_scope_grants' THEN
        actor := NEW.created_by_user_id;
    ELSIF NEW.status IN ('approved', 'rejected') THEN
        actor := NEW.decided_by_user_id;
    ELSE
        RETURN NEW;
    END IF;

    IF actor IS NULL OR NOT EXISTS (
        SELECT 1 FROM memberships m
        WHERE m.org_id = NEW.org_id AND m.user_id = actor
    ) THEN
        RAISE EXCEPTION 'k8s cluster scope actor must be a current member of the stated organization';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_cluster_scope_grants_actor_before_write
    BEFORE INSERT OR UPDATE OF org_id, created_by_user_id ON k8s_cluster_scope_grants
    FOR EACH ROW EXECUTE FUNCTION k8s_cluster_scope_actor_require_org_membership();

-- Every membership retains the immutable Service UID and exact L4 tuple.  The
-- foreign key identifies the child whose VIP may be compiled, while the
-- immutable fields prevent a delete/recreate, protocol, or port change from
-- inheriting a prior approval.  A Service deleted from live inventory simply
-- produces no compiler output; the historical row remains auditable.
CREATE TABLE k8s_cluster_scope_memberships (
    rule_id             uuid        NOT NULL,
    org_id              uuid        NOT NULL,
    cluster_id          uuid        NOT NULL,
    service_child_id    uuid        NOT NULL REFERENCES k8s_services (id) ON DELETE RESTRICT,
    namespace           text        NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 63 AND namespace !~ '[[:cntrl:]]'),
    service_uid         text        NOT NULL CHECK (octet_length(service_uid) BETWEEN 1 AND 253 AND service_uid !~ '[[:cntrl:]]'),
    protocol            text        NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    port_low            integer     NOT NULL CHECK (port_low BETWEEN 1 AND 65535),
    port_high           integer     NOT NULL CHECK (port_high = port_low),
    status              text        NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    decided_by_user_id  uuid        REFERENCES users (id) ON DELETE RESTRICT,
    decided_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, service_child_id),
    FOREIGN KEY (rule_id, org_id, cluster_id)
        REFERENCES k8s_cluster_scope_grants (rule_id, org_id, cluster_id) ON DELETE CASCADE,
    CHECK (
        (status = 'pending' AND decided_by_user_id IS NULL AND decided_at IS NULL)
     OR (status IN ('approved', 'rejected') AND decided_by_user_id IS NOT NULL AND decided_at IS NOT NULL)
    )
);
CREATE INDEX k8s_cluster_scope_memberships_pending_idx
    ON k8s_cluster_scope_memberships (org_id, cluster_id, created_at, rule_id, service_child_id)
    WHERE status = 'pending';
CREATE INDEX k8s_cluster_scope_memberships_approved_idx
    ON k8s_cluster_scope_memberships (org_id, cluster_id, service_child_id)
    WHERE status = 'approved';
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_cluster_scope_memberships
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Membership identity is copied from the current, server-authoritative exact
-- child and UID ledger. A raw writer cannot substitute a sibling port/protocol
-- or a recreated Service UID and make it look approved.
CREATE FUNCTION k8s_cluster_scope_membership_require_live_identity() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM k8s_services s
        JOIN k8s_service_identities i ON i.id=s.identity_id AND i.org_id=s.org_id
        JOIN k8s_service_uid_observation_ledgers l
          ON l.org_id=s.org_id AND l.cluster_id=s.cluster_id
        JOIN k8s_service_uid_observation_current u
          ON u.ledger_id=l.id AND u.org_id=l.org_id
             AND u.namespace=s.namespace AND u.service=i.name AND u.state='live'
        WHERE s.id=NEW.service_child_id AND s.org_id=NEW.org_id
          AND s.cluster_id=NEW.cluster_id AND s.deleted_at IS NULL
          AND NEW.namespace=s.namespace AND NEW.service_uid=u.uid
          AND NEW.protocol=s.protocol AND NEW.port_low=s.port_low
          AND NEW.port_high=s.port_high
    ) THEN
        RAISE EXCEPTION 'k8s cluster scope membership is not the current exact Service identity';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE FUNCTION k8s_cluster_scope_membership_identity_immutable() RETURNS trigger AS $$
BEGIN
    IF OLD.rule_id IS DISTINCT FROM NEW.rule_id
       OR OLD.org_id IS DISTINCT FROM NEW.org_id
       OR OLD.cluster_id IS DISTINCT FROM NEW.cluster_id
       OR OLD.service_child_id IS DISTINCT FROM NEW.service_child_id
       OR OLD.namespace IS DISTINCT FROM NEW.namespace
       OR OLD.service_uid IS DISTINCT FROM NEW.service_uid
       OR OLD.protocol IS DISTINCT FROM NEW.protocol
       OR OLD.port_low IS DISTINCT FROM NEW.port_low
       OR OLD.port_high IS DISTINCT FROM NEW.port_high THEN
        RAISE EXCEPTION 'k8s cluster-scope membership identity is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_cluster_scope_memberships_require_live_identity_before_insert
    BEFORE INSERT ON k8s_cluster_scope_memberships
    FOR EACH ROW EXECUTE FUNCTION k8s_cluster_scope_membership_require_live_identity();
CREATE TRIGGER k8s_cluster_scope_memberships_identity_before_update
    BEFORE UPDATE ON k8s_cluster_scope_memberships
    FOR EACH ROW EXECUTE FUNCTION k8s_cluster_scope_membership_identity_immutable();

-- All capacity refusals are explicit: no INSERT path may truncate a scope or
-- silently omit a later pending decision.  Initial selection is checked by the
-- service under the same transaction; the database independently enforces its
-- durable ceilings for every writer.
CREATE FUNCTION k8s_cluster_scope_bound_write() RETURNS trigger AS $$
DECLARE
    scope_count integer;
    membership_count integer;
    pending_for_child integer;
BEGIN
    IF TG_TABLE_NAME = 'k8s_cluster_scope_grants' THEN
        -- Serialize active-scope cardinality per cluster.  The service also
        -- takes this row lock before reading candidates; the trigger prevents
        -- a second SQL writer from bypassing that transaction discipline.
        PERFORM 1 FROM k8s_clusters WHERE id = NEW.cluster_id FOR UPDATE;
        IF NEW.active AND NOT EXISTS (SELECT 1 FROM k8s_cluster_scope_grants
          WHERE org_id = NEW.org_id AND cluster_id = NEW.cluster_id AND active
            AND rule_id <> NEW.rule_id LIMIT 1) THEN
            RETURN NEW;
        END IF;
        IF NEW.active THEN
            SELECT count(*) INTO scope_count FROM k8s_cluster_scope_grants
              WHERE org_id = NEW.org_id AND cluster_id = NEW.cluster_id AND active
                AND rule_id <> NEW.rule_id;
            IF scope_count >= 20 THEN
                RAISE EXCEPTION 'k8s_cluster_scope_limit_reached';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    -- Serialize both the membership ceiling and later-exposure fanout on the
    -- exact Service child.  Distinct ports have distinct children by 0080.
    PERFORM 1 FROM k8s_services WHERE id = NEW.service_child_id FOR UPDATE;
    SELECT count(*) INTO membership_count FROM k8s_cluster_scope_memberships
      WHERE rule_id = NEW.rule_id AND service_child_id <> NEW.service_child_id;
    IF membership_count >= 500 THEN
        RAISE EXCEPTION 'k8s_cluster_scope_membership_limit_reached';
    END IF;
    IF NEW.status = 'pending' THEN
        SELECT count(*) INTO pending_for_child FROM k8s_cluster_scope_memberships
          WHERE org_id = NEW.org_id AND cluster_id = NEW.cluster_id
            AND service_child_id = NEW.service_child_id AND status = 'pending'
            AND rule_id <> NEW.rule_id;
        IF pending_for_child >= 20 THEN
            RAISE EXCEPTION 'k8s_cluster_scope_pending_fanout_limit_reached';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_cluster_scope_grants_bound_before_write
    BEFORE INSERT OR UPDATE OF active, org_id, cluster_id ON k8s_cluster_scope_grants
    FOR EACH ROW EXECUTE FUNCTION k8s_cluster_scope_bound_write();
CREATE TRIGGER k8s_cluster_scope_memberships_bound_before_insert
    BEFORE INSERT ON k8s_cluster_scope_memberships
    FOR EACH ROW EXECUTE FUNCTION k8s_cluster_scope_bound_write();

-- Decisions are one-way.  A repeat with the same terminal status is an
-- idempotent no-op at the service boundary; this guard rejects any raw writer
-- that attempts to change actor/time, reopen, or reverse a human decision.
CREATE FUNCTION k8s_cluster_scope_membership_decision_immutable() RETURNS trigger AS $$
BEGIN
    IF OLD.status IN ('approved', 'rejected') THEN
        IF NEW.status <> OLD.status
           OR NEW.decided_by_user_id IS DISTINCT FROM OLD.decided_by_user_id
           OR NEW.decided_at IS DISTINCT FROM OLD.decided_at THEN
            RAISE EXCEPTION 'k8s cluster-scope decision is immutable';
        END IF;
    ELSIF OLD.status = 'pending' AND NEW.status = 'pending' THEN
        IF NEW.decided_by_user_id IS NOT NULL OR NEW.decided_at IS NOT NULL THEN
            RAISE EXCEPTION 'pending membership cannot carry decision provenance';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_cluster_scope_memberships_decision_before_update
    BEFORE UPDATE ON k8s_cluster_scope_memberships
    FOR EACH ROW EXECUTE FUNCTION k8s_cluster_scope_membership_decision_immutable();
CREATE TRIGGER k8s_cluster_scope_memberships_actor_before_write
    BEFORE INSERT OR UPDATE OF org_id, status, decided_by_user_id ON k8s_cluster_scope_memberships
    FOR EACH ROW EXECUTE FUNCTION k8s_cluster_scope_actor_require_org_membership();
