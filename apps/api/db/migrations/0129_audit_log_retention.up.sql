-- Per-organization audit-log retention. A missing settings row intentionally
-- means retain forever (revision zero), preserving the append-only behavior of
-- every existing installation until an administrator explicitly opts in.

CREATE TABLE audit_log_retention_settings (
    org_id                    uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    retention_days            integer
                              CHECK (retention_days IS NULL OR retention_days BETWEEN 1 AND 3650),
    cleanup_interval_minutes  integer NOT NULL DEFAULT 60
                              CHECK (cleanup_interval_minutes BETWEEN 5 AND 1440),
    revision                  bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by_user_id        uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    created_at                timestamptz NOT NULL DEFAULT now(),
    updated_at                timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON audit_log_retention_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE FUNCTION audit_log_retention_settings_actor_require_membership()
RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM memberships membership
        WHERE membership.org_id=NEW.org_id
          AND membership.user_id=NEW.updated_by_user_id
          AND membership.access_revoked_at IS NULL
        FOR SHARE
    ) THEN
        RAISE EXCEPTION 'audit_log_retention_actor_not_organization_member';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_retention_settings_actor_before_write
    BEFORE INSERT OR UPDATE ON audit_log_retention_settings
    FOR EACH ROW EXECUTE FUNCTION audit_log_retention_settings_actor_require_membership();

-- Runs exist only for a bounded policy. Each row is a durable snapshot of the
-- exact policy used by one scheduled or manually requested prune.
CREATE TABLE audit_log_retention_runs (
    id                         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id                     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    trigger_kind               text NOT NULL CHECK (trigger_kind IN ('scheduled','manual')),
    status                     text NOT NULL DEFAULT 'running'
                               CHECK (status IN ('running','succeeded','failed')),
    manual_idempotency_key     text,
    requested_by_user_id       uuid REFERENCES users (id) ON DELETE SET NULL,
    retention_days             integer NOT NULL CHECK (retention_days BETWEEN 1 AND 3650),
    cleanup_interval_minutes   integer NOT NULL CHECK (cleanup_interval_minutes BETWEEN 5 AND 1440),
    settings_revision          bigint NOT NULL CHECK (settings_revision > 0),
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
    -- Match Go's fixed 24-hour duration even when the database session timezone
    -- crosses a daylight-saving transition.
    CHECK (cutoff_at = started_at - retention_days * interval '24 hours'),
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
CREATE TRIGGER set_updated_at BEFORE UPDATE ON audit_log_retention_runs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE UNIQUE INDEX audit_log_retention_runs_one_running_org_idx
    ON audit_log_retention_runs (org_id) WHERE status='running';
CREATE UNIQUE INDEX audit_log_retention_runs_manual_key_idx
    ON audit_log_retention_runs (org_id, manual_idempotency_key)
    WHERE manual_idempotency_key IS NOT NULL;
CREATE INDEX audit_log_retention_runs_org_started_idx
    ON audit_log_retention_runs (org_id, started_at DESC, id DESC);
CREATE INDEX audit_log_retention_runs_running_lease_idx
    ON audit_log_retention_runs (lease_expires_at, org_id)
    WHERE status='running';

CREATE FUNCTION audit_log_retention_run_actor_require_membership()
RETURNS trigger AS $$
BEGIN
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
          AND membership.access_revoked_at IS NULL
        FOR SHARE
    ) THEN
        RAISE EXCEPTION 'audit_log_retention_run_actor_not_organization_member';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_retention_runs_actor_before_write
    BEFORE INSERT OR UPDATE ON audit_log_retention_runs
    FOR EACH ROW EXECUTE FUNCTION audit_log_retention_run_actor_require_membership();

-- Ordinary audit rows remain immutable. The only DELETE exception is a row id
-- authorized for this backend and transaction by the security-definer prune
-- function below. UPDATE and TRUNCATE remain impossible.
CREATE TABLE audit_log_retention_authorizations (
    backend_pid     integer NOT NULL,
    transaction_id bigint NOT NULL,
    audit_log_id    uuid PRIMARY KEY,
    created_at      timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON audit_log_retention_authorizations FROM PUBLIC;

CREATE FUNCTION audit_log_retention_authorized(target_audit_log uuid)
RETURNS boolean AS $$
    SELECT EXISTS (
        SELECT 1
        FROM audit_log_retention_authorizations auth_row
        WHERE auth_row.audit_log_id=target_audit_log
          AND auth_row.backend_pid=pg_backend_pid()
          AND auth_row.transaction_id=txid_current()
    );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path=public,pg_temp;
REVOKE ALL ON FUNCTION audit_log_retention_authorized(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION audit_logs_prevent_mutation()
RETURNS trigger AS $$
BEGIN
    IF TG_OP='DELETE' AND audit_log_retention_authorized(OLD.id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_logs is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION audit_log_retention_prune_batch(target_run uuid)
RETURNS bigint AS $$
DECLARE
    target_org uuid;
    older_than timestamptz;
    deleted_count bigint;
BEGIN
    -- Validate and lock the exact durable claim in the same transaction as the
    -- DELETE. A stale worker can never resume after lease expiry or replacement
    -- and delete under an obsolete cutoff. The cutoff is derived from the run,
    -- not accepted from application input.
    SELECT run.org_id,run.cutoff_at
      INTO target_org,older_than
    FROM audit_log_retention_runs run
    JOIN audit_log_retention_settings setting
      ON setting.org_id=run.org_id
     AND setting.revision=run.settings_revision
     AND setting.retention_days=run.retention_days
     AND setting.cleanup_interval_minutes=run.cleanup_interval_minutes
    WHERE run.id=target_run
      AND run.status='running'
      AND run.lease_expires_at > statement_timestamp()
      AND run.batches < run.max_batches
      AND run.started_at <= statement_timestamp()
      AND run.cutoff_at <= statement_timestamp()
          - run.retention_days * interval '24 hours'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit_log_retention_run_not_owned';
    END IF;

    INSERT INTO audit_log_retention_authorizations
        (backend_pid,transaction_id,audit_log_id)
    SELECT pg_backend_pid(),txid_current(),candidate.id
    FROM (
        SELECT audit.id
        FROM audit_logs audit
        WHERE audit.org_id=target_org AND audit.created_at < older_than
          -- Handoff CAS rows are immutable foreign-key evidence for a durable
          -- operation. Preserve them instead of letting the oldest pinned row
          -- poison every bounded batch with an ON DELETE RESTRICT failure.
          AND NOT EXISTS (
              SELECT 1 FROM k8s_connector_handoff_operations operation
              WHERE operation.cas_audit_id=audit.id
                AND operation.org_id=audit.org_id
          )
        ORDER BY audit.created_at,audit.id
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
    ) candidate;

    DELETE FROM audit_logs audit
    USING audit_log_retention_authorizations auth_row
    WHERE auth_row.audit_log_id=audit.id
      AND auth_row.backend_pid=pg_backend_pid()
      AND auth_row.transaction_id=txid_current();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;

    -- Record deletion truth in the same transaction as the irreversible
    -- DELETE. If the worker dies before finalization, lease expiry can still
    -- report the exact committed row and batch counts.
    IF deleted_count > 0 THEN
        UPDATE audit_log_retention_runs run
        SET deleted_rows=run.deleted_rows + deleted_count,
            batches=run.batches + 1
        WHERE run.id=target_run;
    END IF;

    DELETE FROM audit_log_retention_authorizations
    WHERE backend_pid=pg_backend_pid() AND transaction_id=txid_current();
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp;
REVOKE ALL ON FUNCTION audit_log_retention_prune_batch(uuid) FROM PUBLIC;
