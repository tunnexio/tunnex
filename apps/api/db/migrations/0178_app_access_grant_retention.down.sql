LOCK TABLE organizations IN EXCLUSIVE MODE;
LOCK TABLE app_access_grants IN SHARE ROW EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM app_access_retention_runs) OR EXISTS(SELECT 1 FROM app_access_requests WHERE approved_grant_id IS NOT NULL AND grant_id IS NULL) THEN
  RAISE EXCEPTION 'app_access_retention_history_requires_preservation';
 END IF;
END $$;
DROP FUNCTION app_access_retention_prune_batch(uuid);
DROP TRIGGER app_access_retention_run_guard ON app_access_retention_runs;
DROP FUNCTION app_access_retention_run_guard();
DROP TABLE app_access_retention_batch_authorizations;
DROP TABLE app_access_retention_runs;
DROP FUNCTION app_access_retention_has_work(uuid,timestamptz,timestamptz);
DROP INDEX app_access_grant_audit_retention;
DROP INDEX app_access_grants_retention;
DROP TRIGGER app_access_request_grant_snapshot ON app_access_requests;
DROP FUNCTION app_access_request_grant_snapshot();
ALTER TABLE app_access_requests DROP COLUMN approved_grant_id;
CREATE OR REPLACE FUNCTION app_access_grant_subject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.org_id<>OLD.org_id OR NEW.app_id<>OLD.app_id OR NEW.subject_kind<>OLD.subject_kind OR NEW.subject_id<>OLD.subject_id THEN RAISE EXCEPTION 'App Access grant subject is immutable' USING ERRCODE='23514'; END IF;
 IF (OLD.user_id IS NOT NULL AND NEW.user_id IS NULL) OR (OLD.group_id IS NOT NULL AND NEW.group_id IS NULL) THEN
  NEW.enabled=false; NEW.revoked_at=coalesce(OLD.revoked_at,now()); NEW.version=OLD.version+1; NEW.updated_at=now();
  INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata) VALUES(OLD.org_id,'app-access-subject-removal','app_access.grant_subject_removed','app_access',OLD.id::text,jsonb_build_object('version',NEW.version,'subject_kind',OLD.subject_kind));
 END IF;
 RETURN NEW;
END $$;

DROP FUNCTION app_access_grant_snapshot(app_access_grants);
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
