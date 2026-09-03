-- Retention policy and run history are operator-visible state. Refuse a
-- destructive rollback once the feature has been configured or used.
LOCK TABLE audit_log_retention_runs,
           audit_log_retention_settings,
           audit_log_retention_authorizations,
           audit_logs
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM audit_log_retention_settings)
       OR EXISTS (SELECT 1 FROM audit_log_retention_runs)
       OR EXISTS (SELECT 1 FROM audit_log_retention_authorizations) THEN
        RAISE EXCEPTION 'cannot roll back 0129: audit-log retention state exists';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION audit_logs_prevent_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP FUNCTION audit_log_retention_prune_batch(uuid);
DROP FUNCTION audit_log_retention_authorized(uuid);
DROP TABLE audit_log_retention_authorizations;

DROP TABLE audit_log_retention_runs;
DROP FUNCTION audit_log_retention_run_actor_require_membership();
DROP TABLE audit_log_retention_settings;
DROP FUNCTION audit_log_retention_settings_actor_require_membership();
