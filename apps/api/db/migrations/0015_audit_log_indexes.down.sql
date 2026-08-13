DROP INDEX IF EXISTS audit_logs_org_action_created_idx;
DROP INDEX IF EXISTS audit_logs_org_actor_created_idx;
DROP INDEX IF EXISTS audit_logs_org_created_id_idx;
CREATE INDEX audit_logs_org_id_created_at_idx ON audit_logs (org_id, created_at DESC);
