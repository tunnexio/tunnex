-- Tenant-scoped access-event retention policy and durable execution history.
-- A missing settings row intentionally means the frozen application defaults
-- (30 days, hourly cleanup, revision zero); only explicit operator changes are
-- persisted. Runs snapshot the effective policy so their result remains
-- intelligible after a later settings change.

CREATE TABLE access_event_retention_settings (
    org_id                    uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    retention_days            integer NOT NULL DEFAULT 30
                              CHECK (retention_days BETWEEN 1 AND 3650),
    cleanup_interval_minutes  integer NOT NULL DEFAULT 60
                              CHECK (cleanup_interval_minutes BETWEEN 5 AND 1440),
    revision                  bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by_user_id        uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    created_at                timestamptz NOT NULL DEFAULT now(),
    updated_at                timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON access_event_retention_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A globally valid user id is not enough attribution for tenant configuration:
-- the actor must belong to the organization at the time of the write. A later
-- membership removal deliberately does not rewrite or erase historical actor
-- attribution.
CREATE FUNCTION access_event_retention_settings_actor_require_membership()
RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM memberships membership
        WHERE membership.org_id=NEW.org_id
          AND membership.user_id=NEW.updated_by_user_id
        FOR SHARE
    ) THEN
        RAISE EXCEPTION 'access_event_retention_actor_not_organization_member';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER access_event_retention_settings_actor_before_write
    BEFORE INSERT OR UPDATE ON access_event_retention_settings
    FOR EACH ROW EXECUTE FUNCTION access_event_retention_settings_actor_require_membership();

CREATE TABLE access_event_retention_runs (
    id                         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id                     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    trigger_kind               text NOT NULL CHECK (trigger_kind IN ('scheduled','manual')),
    status                     text NOT NULL DEFAULT 'running'
                               CHECK (status IN ('running','succeeded','failed')),
    manual_idempotency_key     text,
    requested_by_user_id       uuid REFERENCES users (id) ON DELETE SET NULL,

    -- Immutable effective-policy snapshot for this run.
    retention_days             integer NOT NULL CHECK (retention_days BETWEEN 1 AND 3650),
    cleanup_interval_minutes   integer NOT NULL CHECK (cleanup_interval_minutes BETWEEN 5 AND 1440),
    settings_revision          bigint NOT NULL CHECK (settings_revision >= 0),
    row_cap                    integer NOT NULL DEFAULT 100000 CHECK (row_cap = 100000),
    batch_size                 integer NOT NULL DEFAULT 1000 CHECK (batch_size = 1000),
    max_batches                integer NOT NULL DEFAULT 100 CHECK (max_batches = 100),
    cutoff_at                  timestamptz NOT NULL,

    started_at                 timestamptz NOT NULL DEFAULT now(),
    lease_expires_at           timestamptz,
    completed_at               timestamptz,
    deleted_rows               bigint NOT NULL DEFAULT 0 CHECK (deleted_rows >= 0),
    batches                    integer NOT NULL DEFAULT 0 CHECK (batches BETWEEN 0 AND 100),
    more_pending               boolean NOT NULL DEFAULT false,
    error_code                 text CHECK (error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now(),

    CHECK ((trigger_kind='manual' AND manual_idempotency_key IS NOT NULL)
        OR (trigger_kind='scheduled' AND manual_idempotency_key IS NULL)),
    CHECK (manual_idempotency_key IS NULL
        OR (octet_length(manual_idempotency_key) BETWEEN 1 AND 128
            AND manual_idempotency_key ~ '^[A-Za-z0-9._:-]+$')),
    CHECK (cutoff_at <= started_at),
    CHECK (completed_at IS NULL OR completed_at >= started_at),
    CHECK ((status='running'
            AND completed_at IS NULL
            AND lease_expires_at IS NOT NULL
            AND lease_expires_at > started_at
            AND error_code IS NULL)
        OR (status='succeeded'
            AND completed_at IS NOT NULL
            AND lease_expires_at IS NULL
            AND error_code IS NULL)
        OR (status='failed'
            AND completed_at IS NOT NULL
            AND lease_expires_at IS NULL
            AND error_code IS NOT NULL))
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON access_event_retention_runs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Exactly one worker may own a tenant's prune at a time. Manual idempotency is
-- tenant-local: the same client key in two organizations denotes two requests.
CREATE UNIQUE INDEX access_event_retention_runs_one_running_org_idx
    ON access_event_retention_runs (org_id) WHERE status='running';
CREATE UNIQUE INDEX access_event_retention_runs_manual_key_idx
    ON access_event_retention_runs (org_id, manual_idempotency_key)
    WHERE manual_idempotency_key IS NOT NULL;
CREATE INDEX access_event_retention_runs_org_started_idx
    ON access_event_retention_runs (org_id, started_at DESC, id DESC);
CREATE INDEX access_event_retention_runs_running_lease_idx
    ON access_event_retention_runs (lease_expires_at, org_id)
    WHERE status='running';

CREATE FUNCTION access_event_retention_run_actor_require_membership()
RETURNS trigger AS $$
BEGIN
    -- Lease renewal/finalization updates operational fields only. Historical
    -- attribution must remain writable after the requester leaves the tenant;
    -- revalidate only an INSERT or an attempted actor/tenant reassignment.
    IF TG_OP='UPDATE' THEN
        IF NEW.org_id IS NOT DISTINCT FROM OLD.org_id
           AND NEW.requested_by_user_id IS NOT DISTINCT FROM OLD.requested_by_user_id THEN
            RETURN NEW;
        END IF;
    END IF;
    IF NEW.requested_by_user_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM memberships membership
        WHERE membership.org_id=NEW.org_id
          AND membership.user_id=NEW.requested_by_user_id
        FOR SHARE
    ) THEN
        RAISE EXCEPTION 'access_event_retention_run_actor_not_organization_member';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER access_event_retention_runs_actor_before_write
    BEFORE INSERT OR UPDATE ON access_event_retention_runs
    FOR EACH ROW EXECUTE FUNCTION access_event_retention_run_actor_require_membership();
