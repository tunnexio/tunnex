-- Match 0130 up and runtime's root-first lock order before touching children.
LOCK TABLE organizations IN EXCLUSIVE MODE;
LOCK TABLE access_event_retention_runs,
           access_event_retention_settings,
           access_event_retention_state,
           access_event_retention_authorizations,
           access_events,
           audit_log_retention_runs,
           audit_log_retention_settings,
           audit_log_retention_authorizations
    IN ACCESS EXCLUSIVE MODE;

DROP TRIGGER audit_log_retention_runs_lease_guard_before_update ON audit_log_retention_runs;
DROP FUNCTION audit_log_retention_run_lease_guard();
DROP TRIGGER access_event_retention_runs_lease_guard_before_update ON access_event_retention_runs;
DROP FUNCTION access_event_retention_run_lease_guard();

DROP TRIGGER access_event_retention_state_delete ON access_events;
DROP TRIGGER access_event_retention_state_insert ON access_events;
DROP FUNCTION access_event_retention_state_after_delete();
DROP FUNCTION access_event_retention_state_after_insert();
DROP TABLE access_event_retention_state;

DROP TRIGGER access_events_truncate_guard ON access_events;
DROP TRIGGER access_events_delete_guard ON access_events;
DROP FUNCTION access_events_prevent_unauthorized_delete();
DROP FUNCTION access_event_retention_prune_batch(uuid);
DROP FUNCTION access_event_retention_authorized(uuid);
DROP TABLE access_event_retention_authorizations;

-- Restore 0127's actor predicates exactly. This is intentionally less strict,
-- but makes the down migration a faithful reversal of 0130.
CREATE OR REPLACE FUNCTION access_event_retention_settings_actor_require_membership()
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
        FOR SHARE
    ) THEN
        RAISE EXCEPTION 'access_event_retention_run_actor_not_organization_member';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Restore migration 0129's audit pruning definition exactly. The function's
-- existing ACL remains unchanged, including the PUBLIC EXECUTE revocation.
CREATE OR REPLACE FUNCTION audit_log_retention_prune_batch(target_run uuid)
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
