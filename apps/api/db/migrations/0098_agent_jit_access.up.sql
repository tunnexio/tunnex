-- F10: approval-gated, bounded temporary access for managed agents. Approved
-- requests materialize ordinary expiring policy_rules; this schema records the
-- workflow and provenance, not another enforcement model.

ALTER TABLE organizations
    ADD COLUMN agent_jit_access_enabled boolean NOT NULL DEFAULT false;

CREATE TABLE agent_access_requests (
    id                         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id                     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    device_id                  uuid NOT NULL,
    dst_kind                   text NOT NULL CHECK (dst_kind IN ('resource', 'group', 'site', 'k8s_service')),
    dst_resource_id            uuid,
    dst_group_id               uuid,
    dst_site_id                uuid,
    dst_k8s_service_id         uuid,
    dst_name                   text NOT NULL CHECK (length(btrim(dst_name)) >= 1),
    reason                     text NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 500),
    requested_duration_seconds integer NOT NULL CHECK (requested_duration_seconds BETWEEN 300 AND 86400),
    state                      text NOT NULL DEFAULT 'pending'
                               CHECK (state IN ('pending', 'approved', 'rejected', 'cancelled', 'expired', 'revoked')),
    requested_by_user_id       uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    requested_at               timestamptz NOT NULL DEFAULT now(),
    approved_by_user_id        uuid REFERENCES users (id) ON DELETE RESTRICT,
    approved_at                timestamptz,
    approved_expires_at        timestamptz,
    rejected_by_user_id        uuid REFERENCES users (id) ON DELETE RESTRICT,
    rejected_at                timestamptz,
    rejection_reason           text CHECK (rejection_reason IS NULL OR length(btrim(rejection_reason)) BETWEEN 1 AND 500),
    cancelled_by_user_id       uuid REFERENCES users (id) ON DELETE RESTRICT,
    cancelled_at               timestamptz,
    revoked_by_user_id         uuid REFERENCES users (id) ON DELETE RESTRICT,
    revoked_at                 timestamptz,
    policy_rule_id             uuid,
    updated_at                 timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id),
    FOREIGN KEY (device_id, org_id)
        REFERENCES devices (id, org_id) ON DELETE RESTRICT,
    CHECK (
        (dst_kind = 'resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
     OR (dst_kind = 'group' AND dst_group_id IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
     OR (dst_kind = 'site' AND dst_site_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_k8s_service_id IS NULL)
     OR (dst_kind = 'k8s_service' AND dst_k8s_service_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL)
    ),
    CHECK (
        (state = 'pending' AND approved_at IS NULL AND approved_expires_at IS NULL AND policy_rule_id IS NULL
                           AND rejected_at IS NULL AND cancelled_at IS NULL AND revoked_at IS NULL)
     OR (state = 'approved' AND approved_by_user_id IS NOT NULL AND approved_at IS NOT NULL
                            AND approved_expires_at IS NOT NULL AND policy_rule_id IS NOT NULL
                            AND rejected_at IS NULL AND cancelled_at IS NULL AND revoked_at IS NULL)
     OR (state = 'rejected' AND rejected_by_user_id IS NOT NULL AND rejected_at IS NOT NULL
                            AND rejection_reason IS NOT NULL AND approved_at IS NULL
                            AND cancelled_at IS NULL AND revoked_at IS NULL AND policy_rule_id IS NULL)
     OR (state = 'cancelled' AND cancelled_by_user_id IS NOT NULL AND cancelled_at IS NOT NULL
                             AND approved_at IS NULL AND rejected_at IS NULL
                             AND revoked_at IS NULL AND policy_rule_id IS NULL)
     OR (state = 'expired' AND approved_by_user_id IS NOT NULL AND approved_at IS NOT NULL
                           AND approved_expires_at IS NOT NULL AND policy_rule_id IS NOT NULL
                           AND rejected_at IS NULL AND cancelled_at IS NULL AND revoked_at IS NULL)
     OR (state = 'revoked' AND approved_by_user_id IS NOT NULL AND approved_at IS NOT NULL
                           AND approved_expires_at IS NOT NULL AND policy_rule_id IS NOT NULL
                           AND revoked_by_user_id IS NOT NULL AND revoked_at IS NOT NULL
                           AND rejected_at IS NULL AND cancelled_at IS NULL)
    ),
    CHECK (approved_expires_at IS NULL OR approved_expires_at > approved_at)
);

CREATE INDEX agent_access_requests_org_state_requested_idx
    ON agent_access_requests (org_id, state, requested_at DESC, id DESC);
CREATE INDEX agent_access_requests_org_device_requested_idx
    ON agent_access_requests (org_id, device_id, requested_at DESC, id DESC);
CREATE INDEX agent_access_requests_due_idx
    ON agent_access_requests (approved_expires_at, org_id)
    WHERE state = 'approved';
CREATE UNIQUE INDEX agent_access_requests_live_rule_key
    ON agent_access_requests (org_id, policy_rule_id)
    WHERE policy_rule_id IS NOT NULL;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_access_requests
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE FUNCTION agent_access_request_require_managed_agent() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = NEW.device_id
          AND d.org_id = NEW.org_id
          AND d.kind = 'agent'
          AND d.status IN ('active', 'suspended')
          AND d.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'agent access request requires a live managed agent in the stated organization';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER agent_access_requests_require_managed_agent_before_write
    BEFORE INSERT OR UPDATE OF org_id, device_id ON agent_access_requests
    FOR EACH ROW EXECUTE FUNCTION agent_access_request_require_managed_agent();

CREATE FUNCTION agent_access_request_snapshot_destination() RETURNS trigger AS $$
BEGIN
    CASE NEW.dst_kind
    WHEN 'resource' THEN
        SELECT name INTO STRICT NEW.dst_name FROM resources
        WHERE id = NEW.dst_resource_id AND org_id = NEW.org_id FOR KEY SHARE;
    WHEN 'group' THEN
        SELECT name INTO STRICT NEW.dst_name FROM user_groups
        WHERE id = NEW.dst_group_id AND org_id = NEW.org_id FOR KEY SHARE;
    WHEN 'site' THEN
        SELECT name INTO STRICT NEW.dst_name FROM sites
        WHERE id = NEW.dst_site_id AND org_id = NEW.org_id FOR KEY SHARE;
    WHEN 'k8s_service' THEN
        SELECT name INTO STRICT NEW.dst_name FROM k8s_services
        WHERE id = NEW.dst_k8s_service_id AND org_id = NEW.org_id
          AND deleted_at IS NULL FOR KEY SHARE;
    END CASE;
    RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
    RAISE EXCEPTION 'agent access destination does not exist in the stated organization';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER agent_access_requests_snapshot_destination_before_write
    BEFORE INSERT OR UPDATE OF org_id, dst_kind, dst_resource_id, dst_group_id,
        dst_site_id, dst_k8s_service_id ON agent_access_requests
    FOR EACH ROW EXECUTE FUNCTION agent_access_request_snapshot_destination();

CREATE FUNCTION agent_access_request_destination_snapshot_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'agent access destination snapshots are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER agent_access_requests_destination_snapshot_no_update
    BEFORE UPDATE OF dst_name ON agent_access_requests
    FOR EACH ROW WHEN (OLD.dst_name IS DISTINCT FROM NEW.dst_name)
    EXECUTE FUNCTION agent_access_request_destination_snapshot_immutable();

CREATE TABLE agent_access_request_events (
    id                uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id            uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    request_id        uuid NOT NULL,
    state             text NOT NULL CHECK (state IN ('pending', 'approved', 'rejected', 'cancelled', 'expired', 'revoked')),
    actor_user_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    actor_system      text,
    metadata          jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (request_id, org_id)
        REFERENCES agent_access_requests (id, org_id) ON DELETE RESTRICT,
    CHECK ((actor_user_id IS NOT NULL AND actor_system IS NULL)
        OR (actor_user_id IS NULL AND actor_system IS NOT NULL)),
    CHECK (actor_system IS NULL OR length(actor_system) BETWEEN 1 AND 100),
    CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX agent_access_request_events_org_request_idx
    ON agent_access_request_events (org_id, request_id, created_at, id);

CREATE FUNCTION agent_access_request_events_prevent_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'agent_access_request_events is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER agent_access_request_events_no_update
    BEFORE UPDATE ON agent_access_request_events
    FOR EACH ROW EXECUTE FUNCTION agent_access_request_events_prevent_mutation();
CREATE TRIGGER agent_access_request_events_no_delete
    BEFORE DELETE ON agent_access_request_events
    FOR EACH ROW EXECUTE FUNCTION agent_access_request_events_prevent_mutation();
CREATE TRIGGER agent_access_request_events_no_truncate
    BEFORE TRUNCATE ON agent_access_request_events
    FOR EACH STATEMENT EXECUTE FUNCTION agent_access_request_events_prevent_mutation();

CREATE TABLE agent_access_request_operations (
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    request_id      uuid NOT NULL,
    operation       text NOT NULL CHECK (operation IN ('create', 'approve', 'reject', 'cancel', 'revoke')),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    parameter_hash  text NOT NULL CHECK (parameter_hash ~ '^[0-9a-f]{64}$'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, operation, idempotency_key),
    FOREIGN KEY (request_id, org_id)
        REFERENCES agent_access_requests (id, org_id) ON DELETE RESTRICT
);
CREATE INDEX agent_access_request_operations_request_idx
    ON agent_access_request_operations (org_id, request_id, created_at);
