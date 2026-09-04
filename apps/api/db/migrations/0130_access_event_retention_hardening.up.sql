-- Harden access-event retention at the database boundary. 0127 introduced
-- per-organization policy, but its application-issued DELETE statements were
-- not tied to the durable run that authorized them. That also left the legacy
-- v0.1.19 fixed-30-day sweeper able to erase evidence during a mixed-version
-- rollout after a newer replica had selected a longer policy.

-- Runtime mutations take a tenant row lock before touching retention/event
-- children. Acquire a conflicting table lock on the tenant root before any
-- child-table DDL or backfill, preserving that global lock order and excluding
-- an in-flight hard-delete cascade.
LOCK TABLE organizations IN EXCLUSIVE MODE;
LOCK TABLE access_events IN SHARE ROW EXCLUSIVE MODE;

-- Membership is live authority, not only historical attribution. Preserve the
-- actor UUID after a later revocation, but reject a settings change or new
-- manual run when the actor's organization access has already been revoked.
CREATE OR REPLACE FUNCTION access_event_retention_settings_actor_require_membership()
RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM memberships membership
        WHERE membership.org_id=NEW.org_id
          AND membership.user_id=NEW.updated_by_user_id
          AND membership.access_revoked_at IS NULL
        FOR SHARE
    ) THEN
        RAISE EXCEPTION 'access_event_retention_actor_not_organization_member';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION access_event_retention_run_actor_require_membership()
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
        RAISE EXCEPTION 'access_event_retention_run_actor_not_organization_member';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- v0.1.20 supplied application-clock lease and completion timestamps, as well
-- as process-local deletion counters, to otherwise unfenced UPDATEs. Treat the
-- database row as the authority after PostgreSQL has acquired its tuple lock:
-- normalize live renew/finalize timestamps, preserve committed counters, and
-- permit expiry only when the old lease is actually expired by the post-lock
-- database clock. The prune function's counter increment is the sole running
-- mutation and must match this transaction's exact delete authorizations.
CREATE FUNCTION access_event_retention_run_lease_guard()
RETURNS trigger AS $$
DECLARE
    guard_time      timestamptz;
    base_unchanged  boolean;
BEGIN
    IF OLD.status <> 'running' THEN
        RETURN NEW;
    END IF;

    guard_time := clock_timestamp();
    base_unchanged :=
           NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.org_id IS NOT DISTINCT FROM OLD.org_id
       AND NEW.trigger_kind IS NOT DISTINCT FROM OLD.trigger_kind
       AND NEW.manual_idempotency_key IS NOT DISTINCT FROM OLD.manual_idempotency_key
       AND NEW.retention_days IS NOT DISTINCT FROM OLD.retention_days
       AND NEW.cleanup_interval_minutes IS NOT DISTINCT FROM OLD.cleanup_interval_minutes
       AND NEW.settings_revision IS NOT DISTINCT FROM OLD.settings_revision
       AND NEW.row_cap IS NOT DISTINCT FROM OLD.row_cap
       AND NEW.batch_size IS NOT DISTINCT FROM OLD.batch_size
       AND NEW.max_batches IS NOT DISTINCT FROM OLD.max_batches
       AND NEW.cutoff_at IS NOT DISTINCT FROM OLD.cutoff_at
       AND NEW.started_at IS NOT DISTINCT FROM OLD.started_at
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at;
    IF NOT base_unchanged THEN
        RAISE EXCEPTION 'access_event_retention_run_not_owned';
    END IF;

    -- Preserve the requested_by_user_id ON DELETE SET NULL referential action
    -- for an in-flight manual run. The parent is already absent when the FK
    -- action fires; a direct attempt to erase live attribution is rejected.
    IF NEW.requested_by_user_id IS DISTINCT FROM OLD.requested_by_user_id THEN
        IF OLD.requested_by_user_id IS NOT NULL
           AND NEW.requested_by_user_id IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM users requested_by
               WHERE requested_by.id=OLD.requested_by_user_id
           )
           AND NEW.status IS NOT DISTINCT FROM OLD.status
           AND NEW.lease_expires_at IS NOT DISTINCT FROM OLD.lease_expires_at
           AND NEW.completed_at IS NOT DISTINCT FROM OLD.completed_at
           AND NEW.deleted_rows IS NOT DISTINCT FROM OLD.deleted_rows
           AND NEW.batches IS NOT DISTINCT FROM OLD.batches
           AND NEW.more_pending IS NOT DISTINCT FROM OLD.more_pending
           AND NEW.error_code IS NOT DISTINCT FROM OLD.error_code THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'access_event_retention_run_not_owned';
    END IF;

    -- The security-definer prune leaves one authorization per deleted row in
    -- this backend/transaction until after its atomic counter update. Permit
    -- exactly that positive one-batch delta even if the lease expires after
    -- the already-authorized DELETE began.
    IF NEW.status='running'
       AND NEW.lease_expires_at IS NOT DISTINCT FROM OLD.lease_expires_at
       AND NEW.completed_at IS NOT DISTINCT FROM OLD.completed_at
       AND NEW.more_pending IS NOT DISTINCT FROM OLD.more_pending
       AND NEW.error_code IS NOT DISTINCT FROM OLD.error_code
       AND NEW.batches=OLD.batches + 1
       AND NEW.deleted_rows > OLD.deleted_rows
       AND NEW.deleted_rows - OLD.deleted_rows <= OLD.batch_size
       AND NEW.deleted_rows - OLD.deleted_rows = (
           SELECT count(*)
           FROM access_event_retention_authorizations auth_row
           WHERE auth_row.backend_pid=pg_backend_pid()
             AND auth_row.transaction_id=txid_current()
       ) THEN
        RETURN NEW;
    END IF;

    -- Expiry is recovery, not a caller-clock decision. A forward-skewed old
    -- binary cannot terminate a database-live owner. Preserve deletion truth
    -- and replace its proposed completion timestamp with database time.
    IF NEW.error_code='lease_expired' THEN
        IF OLD.lease_expires_at IS NOT NULL
           AND OLD.lease_expires_at <= guard_time
           AND NEW.status='failed'
           AND NEW.lease_expires_at IS NULL
           AND NEW.completed_at IS NOT NULL
           AND NEW.more_pending
           AND NEW.deleted_rows IS NOT DISTINCT FROM OLD.deleted_rows
           AND NEW.batches IS NOT DISTINCT FROM OLD.batches THEN
            NEW.completed_at := GREATEST(guard_time,OLD.started_at);
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'access_event_retention_run_not_owned';
    END IF;

    -- Renewal is allowed only for the live owner and can change only its
    -- lease. Ignore any caller-proposed horizon, including v0.1.20's arbitrary
    -- application time, and issue the fixed database-clock lease.
    IF OLD.lease_expires_at IS NOT NULL
       AND OLD.lease_expires_at > guard_time
       AND NEW.status='running'
       AND NEW.lease_expires_at IS NOT NULL
       AND NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at
       AND NEW.completed_at IS NOT DISTINCT FROM OLD.completed_at
       AND NEW.deleted_rows IS NOT DISTINCT FROM OLD.deleted_rows
       AND NEW.batches IS NOT DISTINCT FROM OLD.batches
       AND NEW.more_pending IS NOT DISTINCT FROM OLD.more_pending
       AND NEW.error_code IS NOT DISTINCT FROM OLD.error_code THEN
        NEW.lease_expires_at := guard_time + interval '15 minutes';
        RETURN NEW;
    END IF;

    -- Both old and current finalizers may choose success/failure details, but
    -- only while the lease is live. Completion time and durable deletion
    -- counters always come from the locked database row.
    IF OLD.lease_expires_at IS NOT NULL
       AND OLD.lease_expires_at > guard_time
       AND NEW.lease_expires_at IS NULL
       AND NEW.completed_at IS NOT NULL
       AND (
           (NEW.status='succeeded' AND NEW.error_code IS NULL)
           OR (NEW.status='failed' AND NEW.more_pending
               AND NEW.error_code IS NOT NULL)
       ) THEN
        NEW.completed_at := GREATEST(guard_time,OLD.started_at);
        NEW.deleted_rows := OLD.deleted_rows;
        NEW.batches := OLD.batches;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'access_event_retention_run_not_owned';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp;
REVOKE ALL ON FUNCTION access_event_retention_run_lease_guard() FROM PUBLIC;
CREATE TRIGGER access_event_retention_runs_lease_guard_before_update
    BEFORE UPDATE ON access_event_retention_runs
    FOR EACH ROW EXECUTE FUNCTION access_event_retention_run_lease_guard();

CREATE FUNCTION audit_log_retention_run_lease_guard()
RETURNS trigger AS $$
BEGIN
    -- Preserve the requested_by_user_id ON DELETE SET NULL action even when a
    -- manual run is stranded past lease expiry. Direct attribution clearing
    -- still fails while the referenced user exists.
    IF OLD.status='running'
       AND NEW.requested_by_user_id IS DISTINCT FROM OLD.requested_by_user_id THEN
        IF OLD.requested_by_user_id IS NOT NULL
           AND NEW.requested_by_user_id IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM users requested_by
               WHERE requested_by.id=OLD.requested_by_user_id
           )
           AND NEW.id IS NOT DISTINCT FROM OLD.id
           AND NEW.org_id IS NOT DISTINCT FROM OLD.org_id
           AND NEW.trigger_kind IS NOT DISTINCT FROM OLD.trigger_kind
           AND NEW.manual_idempotency_key IS NOT DISTINCT FROM OLD.manual_idempotency_key
           AND NEW.retention_days IS NOT DISTINCT FROM OLD.retention_days
           AND NEW.cleanup_interval_minutes IS NOT DISTINCT FROM OLD.cleanup_interval_minutes
           AND NEW.settings_revision IS NOT DISTINCT FROM OLD.settings_revision
           AND NEW.batch_size IS NOT DISTINCT FROM OLD.batch_size
           AND NEW.max_batches IS NOT DISTINCT FROM OLD.max_batches
           AND NEW.cutoff_at IS NOT DISTINCT FROM OLD.cutoff_at
           AND NEW.started_at IS NOT DISTINCT FROM OLD.started_at
           AND NEW.status IS NOT DISTINCT FROM OLD.status
           AND NEW.lease_expires_at IS NOT DISTINCT FROM OLD.lease_expires_at
           AND NEW.completed_at IS NOT DISTINCT FROM OLD.completed_at
           AND NEW.deleted_rows IS NOT DISTINCT FROM OLD.deleted_rows
           AND NEW.batches IS NOT DISTINCT FROM OLD.batches
           AND NEW.more_pending IS NOT DISTINCT FROM OLD.more_pending
           AND NEW.error_code IS NOT DISTINCT FROM OLD.error_code
           AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'audit_log_retention_run_not_owned';
    END IF;

    IF OLD.status='running'
       AND OLD.lease_expires_at IS NOT NULL
       AND OLD.lease_expires_at <= clock_timestamp() THEN
        IF NEW.status='failed'
           AND NEW.lease_expires_at IS NULL
           AND NEW.completed_at IS NOT NULL
           AND NEW.more_pending
           AND NEW.error_code='lease_expired'
           AND NEW.id IS NOT DISTINCT FROM OLD.id
           AND NEW.org_id IS NOT DISTINCT FROM OLD.org_id
           AND NEW.trigger_kind IS NOT DISTINCT FROM OLD.trigger_kind
           AND NEW.manual_idempotency_key IS NOT DISTINCT FROM OLD.manual_idempotency_key
           AND NEW.requested_by_user_id IS NOT DISTINCT FROM OLD.requested_by_user_id
           AND NEW.retention_days IS NOT DISTINCT FROM OLD.retention_days
           AND NEW.cleanup_interval_minutes IS NOT DISTINCT FROM OLD.cleanup_interval_minutes
           AND NEW.settings_revision IS NOT DISTINCT FROM OLD.settings_revision
           AND NEW.batch_size IS NOT DISTINCT FROM OLD.batch_size
           AND NEW.max_batches IS NOT DISTINCT FROM OLD.max_batches
           AND NEW.cutoff_at IS NOT DISTINCT FROM OLD.cutoff_at
           AND NEW.started_at IS NOT DISTINCT FROM OLD.started_at
           AND NEW.deleted_rows IS NOT DISTINCT FROM OLD.deleted_rows
           AND NEW.batches IS NOT DISTINCT FROM OLD.batches
           AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'audit_log_retention_run_not_owned';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp;
REVOKE ALL ON FUNCTION audit_log_retention_run_lease_guard() FROM PUBLIC;
CREATE TRIGGER audit_log_retention_runs_lease_guard_before_update
    BEFORE UPDATE ON audit_log_retention_runs
    FOR EACH ROW EXECUTE FUNCTION audit_log_retention_run_lease_guard();

-- Keep an exact per-tenant row count so due checks do not DISTINCT-scan the
-- global evidence table and cap checks do not OFFSET 100000 rows unless the
-- tenant is actually over cap. Hold writes for the backfill/trigger handoff;
-- after this lock is acquired there is no gap in which a row can escape the
-- initial count or the transition-table deltas.
CREATE TABLE access_event_retention_state (
    org_id         uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    retained_rows  bigint NOT NULL DEFAULT 0 CHECK (retained_rows >= 0),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON access_event_retention_state
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

INSERT INTO access_event_retention_state (org_id,retained_rows)
SELECT event.org_id,count(*)
FROM access_events event
GROUP BY event.org_id;

CREATE FUNCTION access_event_retention_state_after_insert()
RETURNS trigger AS $$
BEGIN
    INSERT INTO access_event_retention_state (org_id,retained_rows)
    SELECT inserted.org_id,count(*)
    FROM inserted_events inserted
    GROUP BY inserted.org_id
    ON CONFLICT (org_id) DO UPDATE
    SET retained_rows=access_event_retention_state.retained_rows + EXCLUDED.retained_rows;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp;

CREATE FUNCTION access_event_retention_state_after_delete()
RETURNS trigger AS $$
BEGIN
    UPDATE access_event_retention_state state
    SET retained_rows=state.retained_rows - deleted.row_count
    FROM (
        SELECT removed.org_id,count(*) AS row_count
        FROM deleted_events removed
        GROUP BY removed.org_id
    ) deleted
    WHERE state.org_id=deleted.org_id;

    -- A missing state row is valid only while its parent organization is being
    -- hard-deleted and both child tables are cascading away. Any other miss is
    -- counter drift and must roll the evidence deletion back.
    IF EXISTS (
        SELECT 1
        FROM deleted_events removed
        JOIN organizations organization ON organization.id=removed.org_id
        LEFT JOIN access_event_retention_state state ON state.org_id=removed.org_id
        WHERE state.org_id IS NULL
    ) THEN
        RAISE EXCEPTION 'access_event_retention_state_missing';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp;
CREATE TRIGGER access_event_retention_state_insert
    AFTER INSERT ON access_events
    REFERENCING NEW TABLE AS inserted_events
    FOR EACH STATEMENT EXECUTE FUNCTION access_event_retention_state_after_insert();
CREATE TRIGGER access_event_retention_state_delete
    AFTER DELETE ON access_events
    REFERENCING OLD TABLE AS deleted_events
    FOR EACH STATEMENT EXECUTE FUNCTION access_event_retention_state_after_delete();

-- Only the security-definer prune function can mint a row authorization for
-- this backend and transaction. A direct DELETE from an old or stale control
-- plane therefore fails closed instead of bypassing current tenant policy.
CREATE TABLE access_event_retention_authorizations (
    backend_pid     integer NOT NULL,
    transaction_id bigint NOT NULL,
    access_event_id uuid PRIMARY KEY,
    created_at      timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON access_event_retention_authorizations FROM PUBLIC;

CREATE FUNCTION access_event_retention_authorized(target_access_event uuid)
RETURNS boolean AS $$
    SELECT EXISTS (
        SELECT 1
        FROM access_event_retention_authorizations auth_row
        WHERE auth_row.access_event_id=target_access_event
          AND auth_row.backend_pid=pg_backend_pid()
          AND auth_row.transaction_id=txid_current()
    );
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path=public,pg_temp;
REVOKE ALL ON FUNCTION access_event_retention_authorized(uuid) FROM PUBLIC;

CREATE FUNCTION access_events_prevent_unauthorized_delete()
RETURNS trigger AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        IF access_event_retention_authorized(OLD.id) THEN
            RETURN OLD;
        END IF;
        -- access_events owns an ON DELETE CASCADE FK to organizations. The FK
        -- action runs after the parent row is gone, so this preserves normal
        -- lifecycle cleanup without opening a direct-delete bypass for live or
        -- soft-deleted organizations (both still have a parent row).
        IF NOT EXISTS (
            SELECT 1 FROM organizations organization
            WHERE organization.id=OLD.org_id
        ) THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'access_events_delete_not_authorized';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp;

CREATE TRIGGER access_events_delete_guard
    BEFORE DELETE ON access_events
    FOR EACH ROW EXECUTE FUNCTION access_events_prevent_unauthorized_delete();
-- TRUNCATE bypasses row triggers and cannot express an exact tenant policy.
CREATE TRIGGER access_events_truncate_guard
    BEFORE TRUNCATE ON access_events
    FOR EACH STATEMENT EXECUTE FUNCTION access_events_prevent_unauthorized_delete();

CREATE FUNCTION access_event_retention_prune_batch(target_run uuid)
RETURNS bigint AS $$
DECLARE
    target_org        uuid;
    older_than        timestamptz;
    protected_rows    integer;
    target_batch      integer;
    current_rows      bigint;
    authorized_count  bigint;
    deleted_count     bigint;
    validation_time   timestamptz;
BEGIN
    -- Settings writers, run claimers and event ingestion all take the tenant's
    -- organization-row lock first. Taking the same lock here makes a missing
    -- settings row (the revision-zero defaults) stable while it is validated,
    -- and prevents a policy transition from racing the irreversible DELETE.
    SELECT organization.id
      INTO target_org
    FROM access_event_retention_runs run
    JOIN organizations organization ON organization.id=run.org_id
    WHERE run.id=target_run
    FOR UPDATE OF organization;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'access_event_retention_run_not_owned';
    END IF;

    -- Lock a persisted policy row when present, then lock the exact run. These
    -- lock-acquisition statements deliberately have no lease, policy, cutoff
    -- or budget predicates: those values must be evaluated only after every
    -- possible wait has completed.
    PERFORM 1
    FROM access_event_retention_settings setting
    WHERE setting.org_id=target_org
    FOR UPDATE;
    PERFORM 1
    FROM access_event_retention_runs run
    WHERE run.id=target_run AND run.org_id=target_org
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'access_event_retention_run_not_owned';
    END IF;

    validation_time := clock_timestamp();

    -- Validate the locked durable claim in the same transaction as the DELETE.
    -- A stale worker cannot resume after lease expiry or policy change.
    -- A missing settings row means the frozen defaults: 30 days, hourly,
    -- revision zero. Cutoff is derived by the server but independently fenced
    -- against database time so a forward-skewed application clock cannot make
    -- fresh evidence eligible.
    SELECT run.cutoff_at,run.row_cap,run.batch_size,
           COALESCE(state.retained_rows,0)
      INTO older_than,protected_rows,target_batch,current_rows
    FROM access_event_retention_runs run
    LEFT JOIN access_event_retention_settings setting ON setting.org_id=run.org_id
    LEFT JOIN access_event_retention_state state ON state.org_id=run.org_id
    WHERE run.id=target_run
      AND run.org_id=target_org
      AND run.status='running'
      AND run.lease_expires_at > validation_time
      AND run.batches < run.max_batches
      AND run.started_at <= validation_time
      AND run.cutoff_at <= validation_time
          - run.retention_days * interval '24 hours'
      AND run.retention_days=COALESCE(setting.retention_days,30)
      AND run.cleanup_interval_minutes=COALESCE(setting.cleanup_interval_minutes,60)
      AND run.settings_revision=COALESCE(setting.revision,0)
      AND run.row_cap=100000
      AND run.batch_size=1000
      AND run.max_batches=100;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'access_event_retention_run_not_owned';
    END IF;

    -- Preserve the application contract's age-first behavior. Most pruning is
    -- age-based, so do not pay for a 100000-row cap boundary while even one age
    -- batch remains.
    INSERT INTO access_event_retention_authorizations
        (backend_pid,transaction_id,access_event_id)
    SELECT pg_backend_pid(),txid_current(),candidate.id
    FROM (
        SELECT event.id
        FROM access_events event
        WHERE event.org_id=target_org
          AND event.created_at < older_than
        ORDER BY event.created_at,event.id
        LIMIT target_batch
        FOR UPDATE OF event SKIP LOCKED
    ) candidate;
    GET DIAGNOSTICS authorized_count = ROW_COUNT;

    -- Only a no-age-work call evaluates the cap. The exact retained-row state
    -- skips the OFFSET entirely for tenants already within the protected
    -- window; MATERIALIZED guarantees the boundary is computed once otherwise.
    IF authorized_count=0 AND current_rows > protected_rows THEN
        WITH boundary AS MATERIALIZED (
            SELECT event.created_at,event.id
            FROM access_events event
            WHERE event.org_id=target_org
            ORDER BY event.created_at DESC,event.id DESC
            OFFSET protected_rows
            LIMIT 1
        )
        INSERT INTO access_event_retention_authorizations
            (backend_pid,transaction_id,access_event_id)
        SELECT pg_backend_pid(),txid_current(),candidate.id
        FROM (
            SELECT event.id
            FROM access_events event
            CROSS JOIN boundary
            WHERE event.org_id=target_org
              AND (
                  event.created_at < boundary.created_at
                  OR (event.created_at=boundary.created_at AND event.id <= boundary.id)
              )
            ORDER BY event.created_at,event.id
            LIMIT target_batch
            FOR UPDATE OF event SKIP LOCKED
        ) candidate;
    END IF;

    DELETE FROM access_events event
    USING access_event_retention_authorizations auth_row
    WHERE auth_row.access_event_id=event.id
      AND auth_row.backend_pid=pg_backend_pid()
      AND auth_row.transaction_id=txid_current();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;

    -- Deletion truth commits atomically with the evidence removal. A process
    -- crash before finalization can no longer turn a nonzero delete into a
    -- durable run claiming zero rows and zero batches.
    IF deleted_count > 0 THEN
        UPDATE access_event_retention_runs run
        SET deleted_rows=run.deleted_rows + deleted_count,
            batches=run.batches + 1
        WHERE run.id=target_run;
    END IF;

    DELETE FROM access_event_retention_authorizations
    WHERE backend_pid=pg_backend_pid() AND transaction_id=txid_current();
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp;
REVOKE ALL ON FUNCTION access_event_retention_prune_batch(uuid) FROM PUBLIC;

-- 0129's audit prune used statement_timestamp() in the same SELECT that could
-- wait for its row locks. Replace it in this forward migration so validation
-- observes the wall clock only after every lock wait, without changing audit
-- eligibility, pinned-evidence handling, batch size, counters or error shape.
CREATE OR REPLACE FUNCTION audit_log_retention_prune_batch(target_run uuid)
RETURNS bigint AS $$
DECLARE
    target_org       uuid;
    older_than       timestamptz;
    deleted_count    bigint;
    validation_time  timestamptz;
BEGIN
    SELECT organization.id
      INTO target_org
    FROM audit_log_retention_runs run
    JOIN organizations organization ON organization.id=run.org_id
    WHERE run.id=target_run
    FOR UPDATE OF organization;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit_log_retention_run_not_owned';
    END IF;

    -- Acquire the policy and exact-run locks without any mutable ownership
    -- predicates. A lease can expire while either lock waits.
    PERFORM 1
    FROM audit_log_retention_settings setting
    WHERE setting.org_id=target_org
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit_log_retention_run_not_owned';
    END IF;
    PERFORM 1
    FROM audit_log_retention_runs run
    WHERE run.id=target_run AND run.org_id=target_org
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit_log_retention_run_not_owned';
    END IF;

    validation_time := clock_timestamp();
    SELECT run.cutoff_at
      INTO older_than
    FROM audit_log_retention_runs run
    JOIN audit_log_retention_settings setting
      ON setting.org_id=run.org_id
     AND setting.revision=run.settings_revision
     AND setting.retention_days=run.retention_days
     AND setting.cleanup_interval_minutes=run.cleanup_interval_minutes
    WHERE run.id=target_run
      AND run.org_id=target_org
      AND run.status='running'
      AND run.lease_expires_at > validation_time
      AND run.batches < run.max_batches
      AND run.started_at <= validation_time
      AND run.cutoff_at <= validation_time
          - run.retention_days * interval '24 hours';
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
