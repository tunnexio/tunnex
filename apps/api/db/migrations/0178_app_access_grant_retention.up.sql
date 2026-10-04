-- Fixed App Access evidence policy only: revoked grant rows 90*24h;
-- grant-change audit events 365*24h. No data is purged by this migration.
-- Match tenant-first runtime lock ordering before child DDL/backfill.
LOCK TABLE organizations IN EXCLUSIVE MODE;
LOCK TABLE app_access_grants IN SHARE ROW EXCLUSIVE MODE;
ALTER TABLE app_access_requests ADD COLUMN approved_grant_id uuid;
UPDATE app_access_requests SET approved_grant_id=grant_id WHERE status='approved' AND grant_id IS NOT NULL;
ALTER TABLE app_access_requests ADD CONSTRAINT app_access_request_approved_grant CHECK(approved_grant_id IS NULL OR status='approved');
CREATE FUNCTION app_access_request_grant_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND OLD.approved_grant_id IS NOT NULL THEN
  IF NEW.approved_grant_id IS DISTINCT FROM OLD.approved_grant_id THEN RAISE EXCEPTION 'approved_grant_identity_is_immutable'; END IF;
 ELSIF NEW.grant_id IS NOT NULL THEN
  IF NEW.approved_grant_id IS NOT NULL AND NEW.approved_grant_id<>NEW.grant_id THEN RAISE EXCEPTION 'approved_grant_identity_mismatch'; END IF;
  NEW.approved_grant_id=NEW.grant_id;
 ELSIF NEW.approved_grant_id IS NOT NULL THEN
  RAISE EXCEPTION 'approved_grant_identity_requires_bound_grant';
 END IF;
 IF NEW.grant_id IS NOT NULL AND NEW.grant_id IS DISTINCT FROM NEW.approved_grant_id THEN RAISE EXCEPTION 'approved_grant_identity_mismatch'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER app_access_request_grant_snapshot BEFORE INSERT OR UPDATE ON app_access_requests FOR EACH ROW EXECUTE FUNCTION app_access_request_grant_snapshot();
CREATE FUNCTION app_access_grant_snapshot(g app_access_grants) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT jsonb_build_object('id',g.id,'org_id',g.org_id,'app_id',g.app_id,
  'subject_kind',g.subject_kind,'subject_id',g.subject_id,'subject_label',g.subject_label,
  'enabled',g.enabled,'starts_at',g.starts_at,'expires_at',g.expires_at,
  'revoked_at',g.revoked_at,'version',g.version,'created_at',g.created_at,'updated_at',g.updated_at);
$$;
CREATE OR REPLACE FUNCTION app_access_grant_subject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.org_id<>OLD.org_id OR NEW.app_id<>OLD.app_id OR NEW.subject_kind<>OLD.subject_kind OR NEW.subject_id<>OLD.subject_id THEN RAISE EXCEPTION 'App Access grant subject is immutable' USING ERRCODE='23514'; END IF;
 IF (OLD.user_id IS NOT NULL AND NEW.user_id IS NULL) OR (OLD.group_id IS NOT NULL AND NEW.group_id IS NULL) THEN
  NEW.enabled=false; NEW.revoked_at=COALESCE(OLD.revoked_at,now()); NEW.version=OLD.version+1; NEW.updated_at=now();
  INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata)
  VALUES(OLD.org_id,'app-access-subject-removal','app_access.grant_subject_removed','app_access',OLD.id::text,
   jsonb_build_object('version',NEW.version,'subject_kind',OLD.subject_kind,'snapshot_kind','event_state','grant',app_access_grant_snapshot(NEW)));
 END IF;
 RETURN NEW;
END $$;
CREATE INDEX app_access_grants_retention ON app_access_grants(org_id,revoked_at,id) WHERE revoked_at IS NOT NULL;
CREATE INDEX app_access_grant_audit_retention ON audit_logs(org_id,created_at,id)
 WHERE target_type='app_access' AND action IN ('app_access.grant_created','app_access.grant_updated','app_access.grant_revoked','app_access.grant_subject_removed','app_access.grant_retention_context');
CREATE TABLE app_access_retention_runs(
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 status text NOT NULL DEFAULT 'running' CHECK(status IN ('running','succeeded','failed')),
 started_at timestamptz NOT NULL DEFAULT now(),
 grant_cutoff_at timestamptz NOT NULL,
 audit_cutoff_at timestamptz NOT NULL,
 lease_expires_at timestamptz,
 completed_at timestamptz,
 grants_deleted bigint NOT NULL DEFAULT 0 CHECK(grants_deleted>=0),
 audits_deleted bigint NOT NULL DEFAULT 0 CHECK(audits_deleted>=0),
 batches integer NOT NULL DEFAULT 0 CHECK(batches BETWEEN 0 AND 20),
 more_pending boolean NOT NULL DEFAULT false,
 error_code text CHECK(error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
 CHECK(grant_cutoff_at=started_at-interval '2160 hours'),
 CHECK(audit_cutoff_at=started_at-interval '8760 hours'),
 CHECK((status='running' AND completed_at IS NULL AND lease_expires_at IS NOT NULL AND lease_expires_at>started_at AND error_code IS NULL)
    OR (status='succeeded' AND completed_at IS NOT NULL AND completed_at>=started_at AND lease_expires_at IS NULL AND error_code IS NULL)
    OR (status='failed' AND completed_at IS NOT NULL AND completed_at>=started_at AND lease_expires_at IS NULL AND error_code IS NOT NULL))
);
CREATE UNIQUE INDEX app_access_retention_running ON app_access_retention_runs(org_id) WHERE status='running';
CREATE INDEX app_access_retention_recent ON app_access_retention_runs(org_id,started_at DESC,id DESC);
-- Only the definer prune can authorize a positive batch counter delta.
CREATE TABLE app_access_retention_batch_authorizations(
 backend_pid integer NOT NULL, transaction_id bigint NOT NULL, run_id uuid NOT NULL,
 grants_deleted integer NOT NULL CHECK(grants_deleted BETWEEN 0 AND 500),
 audits_deleted integer NOT NULL CHECK(audits_deleted BETWEEN 0 AND 500),
 PRIMARY KEY(backend_pid,transaction_id,run_id),
 CHECK(grants_deleted+audits_deleted>0)
);
REVOKE ALL ON app_access_retention_batch_authorizations FROM PUBLIC;
CREATE FUNCTION app_access_retention_run_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE guard_time timestamptz:=clock_timestamp(); counters_same boolean;
BEGIN
 IF OLD.status<>'running' OR NEW.id IS DISTINCT FROM OLD.id OR NEW.org_id IS DISTINCT FROM OLD.org_id
  OR NEW.started_at IS DISTINCT FROM OLD.started_at OR NEW.grant_cutoff_at IS DISTINCT FROM OLD.grant_cutoff_at
  OR NEW.audit_cutoff_at IS DISTINCT FROM OLD.audit_cutoff_at THEN
  RAISE EXCEPTION 'app_access_retention_run_not_owned';
 END IF;
 counters_same:=NEW.grants_deleted=OLD.grants_deleted AND NEW.audits_deleted=OLD.audits_deleted AND NEW.batches=OLD.batches;
 -- Exact committed deletion truth remains legal after an authorized batch's
 -- lease expires in flight; no caller can fabricate the protected delta.
 IF NEW.status='running' AND NEW.lease_expires_at IS NOT DISTINCT FROM OLD.lease_expires_at
  AND NEW.completed_at IS NOT DISTINCT FROM OLD.completed_at AND NEW.error_code IS NOT DISTINCT FROM OLD.error_code
  AND NEW.more_pending IS NOT DISTINCT FROM OLD.more_pending AND NEW.batches=OLD.batches+1
  AND EXISTS(SELECT 1 FROM app_access_retention_batch_authorizations auth
   WHERE auth.backend_pid=pg_backend_pid() AND auth.transaction_id=txid_current() AND auth.run_id=OLD.id
    AND auth.grants_deleted=NEW.grants_deleted-OLD.grants_deleted AND auth.audits_deleted=NEW.audits_deleted-OLD.audits_deleted) THEN
  RETURN NEW;
 END IF;
 IF NEW.error_code='lease_expired' THEN
  IF OLD.lease_expires_at<=guard_time AND NEW.status='failed' AND NEW.lease_expires_at IS NULL
   AND NEW.completed_at IS NOT NULL AND NEW.more_pending AND counters_same THEN
   NEW.completed_at:=GREATEST(guard_time,OLD.started_at); RETURN NEW;
  END IF;
  RAISE EXCEPTION 'app_access_retention_run_not_owned';
 END IF;
 IF OLD.lease_expires_at>guard_time AND counters_same THEN
  IF NEW.status='running' AND NEW.lease_expires_at IS NOT NULL AND NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at
   AND NEW.completed_at IS NOT DISTINCT FROM OLD.completed_at AND NEW.error_code IS NOT DISTINCT FROM OLD.error_code
   AND NEW.more_pending IS NOT DISTINCT FROM OLD.more_pending THEN
   NEW.lease_expires_at:=guard_time+interval '15 minutes'; RETURN NEW;
  END IF;
  IF NEW.status IN ('succeeded','failed') AND NEW.lease_expires_at IS NULL AND NEW.completed_at IS NOT NULL THEN
   NEW.completed_at:=GREATEST(guard_time,OLD.started_at); RETURN NEW;
  END IF;
 END IF;
 RAISE EXCEPTION 'app_access_retention_run_not_owned';
END $$;
REVOKE ALL ON FUNCTION app_access_retention_run_guard() FROM PUBLIC;
CREATE TRIGGER app_access_retention_run_guard BEFORE UPDATE ON app_access_retention_runs
 FOR EACH ROW EXECUTE FUNCTION app_access_retention_run_guard();

-- Shared read-only eligibility for the leader, claim and final pending check.
CREATE FUNCTION app_access_retention_has_work(target_org uuid,grant_cutoff timestamptz,audit_cutoff timestamptz)
RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM app_access_grants g WHERE g.org_id=target_org AND g.revoked_at<grant_cutoff)
 OR EXISTS(SELECT 1 FROM audit_logs audit WHERE audit.org_id=target_org AND audit.created_at<audit_cutoff
  AND audit.target_type='app_access' AND audit.action IN ('app_access.grant_created','app_access.grant_updated','app_access.grant_revoked','app_access.grant_subject_removed','app_access.grant_retention_context')
  AND NOT EXISTS(SELECT 1 FROM k8s_connector_handoff_operations operation WHERE operation.org_id=audit.org_id AND operation.cas_audit_id=audit.id));
$$;

-- The general policy never owns this category, even for a shorter policy.
-- All other categories retain their exact prior behavior.
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
          AND NOT COALESCE((audit.target_type='app_access' AND audit.action IN ('app_access.grant_created','app_access.grant_updated','app_access.grant_revoked','app_access.grant_subject_removed','app_access.grant_retention_context')),false)
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

-- One batch owns at most 500 revoked grants and 500 audit rows. Audit deletion
-- still requires backend/transaction authorization of exact row IDs.
CREATE FUNCTION app_access_retention_prune_batch(target_run uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE
 target_org uuid; cutoff_grants timestamptz; cutoff_audits timestamptz;
 validation_time timestamptz; grant_count bigint:=0; audit_count bigint:=0;
 selected_grants uuid[];
BEGIN
 SELECT o.id INTO target_org FROM app_access_retention_runs r JOIN organizations o ON o.id=r.org_id WHERE r.id=target_run FOR UPDATE OF o;
 IF NOT FOUND THEN RAISE EXCEPTION 'app_access_retention_run_not_owned'; END IF;
 PERFORM 1 FROM app_access_retention_runs WHERE id=target_run AND org_id=target_org FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'app_access_retention_run_not_owned'; END IF;
 validation_time:=clock_timestamp();
 SELECT grant_cutoff_at,audit_cutoff_at INTO cutoff_grants,cutoff_audits FROM app_access_retention_runs
 WHERE id=target_run AND org_id=target_org AND status='running' AND lease_expires_at>validation_time
 AND batches<20 AND started_at<=validation_time
 AND grant_cutoff_at<=validation_time-interval '2160 hours' AND audit_cutoff_at<=validation_time-interval '8760 hours';
 IF NOT FOUND THEN RAISE EXCEPTION 'app_access_retention_run_not_owned'; END IF;
 SELECT array_agg(candidate.id) INTO selected_grants FROM (
  SELECT g.id FROM app_access_grants g WHERE g.org_id=target_org AND g.revoked_at<cutoff_grants
  ORDER BY g.revoked_at,g.id LIMIT 500 FOR UPDATE SKIP LOCKED
 ) candidate;
 -- This is new purge-time context, never rewritten historical event metadata.
 INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata)
 SELECT g.org_id,'app-access-retention','app_access.grant_retention_context','app_access',g.id::text,
  jsonb_build_object('version',g.version,'snapshot_kind','retention_context','captured_at',clock_timestamp(),
   'context_note','Final retained row captured before deletion; not historical event state.',
   'grant',app_access_grant_snapshot(g),'retention_run_id',target_run)
 FROM app_access_grants g WHERE g.org_id=target_org AND g.id=ANY(selected_grants);
 DELETE FROM app_access_grants WHERE org_id=target_org AND id=ANY(selected_grants) AND revoked_at<cutoff_grants;
 GET DIAGNOSTICS grant_count=ROW_COUNT;
 INSERT INTO audit_log_retention_authorizations(backend_pid,transaction_id,audit_log_id)
 SELECT pg_backend_pid(),txid_current(),candidate.id FROM (
  SELECT audit.id FROM audit_logs audit WHERE audit.org_id=target_org AND audit.created_at<cutoff_audits
   AND audit.target_type='app_access' AND audit.action IN ('app_access.grant_created','app_access.grant_updated','app_access.grant_revoked','app_access.grant_subject_removed','app_access.grant_retention_context')
   AND NOT EXISTS(SELECT 1 FROM k8s_connector_handoff_operations operation WHERE operation.org_id=audit.org_id AND operation.cas_audit_id=audit.id)
  ORDER BY audit.created_at,audit.id LIMIT 500 FOR UPDATE SKIP LOCKED
 ) candidate;
 DELETE FROM audit_logs audit USING audit_log_retention_authorizations auth_row
 WHERE audit.id=auth_row.audit_log_id AND audit.org_id=target_org AND audit.created_at<cutoff_audits
 AND audit.target_type='app_access' AND audit.action IN ('app_access.grant_created','app_access.grant_updated','app_access.grant_revoked','app_access.grant_subject_removed','app_access.grant_retention_context')
 AND auth_row.backend_pid=pg_backend_pid() AND auth_row.transaction_id=txid_current();
 GET DIAGNOSTICS audit_count=ROW_COUNT;
 DELETE FROM audit_log_retention_authorizations WHERE backend_pid=pg_backend_pid() AND transaction_id=txid_current();
 IF grant_count+audit_count>0 THEN
  INSERT INTO app_access_retention_batch_authorizations(backend_pid,transaction_id,run_id,grants_deleted,audits_deleted)
  VALUES(pg_backend_pid(),txid_current(),target_run,grant_count,audit_count);
  UPDATE app_access_retention_runs SET grants_deleted=grants_deleted+grant_count,audits_deleted=audits_deleted+audit_count,batches=batches+1 WHERE id=target_run;
  DELETE FROM app_access_retention_batch_authorizations WHERE backend_pid=pg_backend_pid() AND transaction_id=txid_current() AND run_id=target_run;
 END IF;
 RETURN grant_count+audit_count;
END $$;
REVOKE ALL ON FUNCTION app_access_retention_prune_batch(uuid) FROM PUBLIC;
