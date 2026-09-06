-- A database that has exercised the install-operation protocol cannot safely
-- run an N-1 control plane. Restore a verified pre-0136 backup instead.
LOCK TABLE node_join_tokens IN ACCESS EXCLUSIVE MODE;
LOCK TABLE node_lifecycle_install_operations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE k8s_lifecycle_install_operation_usage IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_lifecycle_install_operation_usage)
       OR EXISTS (SELECT 1 FROM node_lifecycle_install_operations) THEN
        RAISE EXCEPTION 'cannot roll back 0136 after Kubernetes lifecycle install-operation data exists: this database lifecycle is forward-only; restore a verified pre-0136 backup to run an N-1 control plane';
    END IF;
END $$;

DROP TRIGGER IF EXISTS node_join_tokens_lifecycle_abort_guard_before_update ON node_join_tokens;
DROP FUNCTION IF EXISTS node_lifecycle_guard_token_abort();
DROP TRIGGER IF EXISTS node_join_tokens_lifecycle_remint_guard_before_update ON node_join_tokens;
DROP FUNCTION IF EXISTS node_lifecycle_guard_token_remint();
DROP TRIGGER IF EXISTS node_join_tokens_aa_lifecycle_install_consume_guard_before_update ON node_join_tokens;
DROP FUNCTION IF EXISTS node_lifecycle_guard_token_consumption();

DROP TRIGGER IF EXISTS node_lifecycle_install_operation_usage_after_insert ON node_lifecycle_install_operations;
DROP FUNCTION IF EXISTS mark_k8s_lifecycle_install_operation_usage();
DROP TABLE IF EXISTS k8s_lifecycle_install_operation_usage;

DROP TABLE IF EXISTS node_lifecycle_install_operations;
