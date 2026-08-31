-- Block lifecycle-token consumption and node enrollment before checking that
-- the forward-only provenance columns are empty. The lock order matches the
-- enrollment transaction (token first, then node) and closes the race where a
-- writer could commit claim data after the guard but before DROP COLUMN.
LOCK TABLE node_join_tokens IN ACCESS EXCLUSIVE MODE;
LOCK TABLE nodes IN ACCESS EXCLUSIVE MODE;
LOCK TABLE k8s_lifecycle_claim_usage IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM k8s_lifecycle_claim_usage)
       OR EXISTS (SELECT 1 FROM node_join_tokens WHERE lifecycle_claim IS NOT NULL)
       OR EXISTS (SELECT 1 FROM nodes WHERE lifecycle_claim IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back 0130 after Kubernetes lifecycle claim data exists: this database lifecycle is forward-only; restore a verified pre-0130 backup to run an N-1 control plane';
    END IF;
END $$;

DROP TRIGGER IF EXISTS node_join_tokens_lifecycle_usage_after_insert ON node_join_tokens;
DROP TRIGGER IF EXISTS node_join_tokens_lifecycle_usage_after_update ON node_join_tokens;
DROP TRIGGER IF EXISTS nodes_lifecycle_usage_after_insert ON nodes;
DROP TRIGGER IF EXISTS nodes_lifecycle_usage_after_update ON nodes;
DROP FUNCTION IF EXISTS mark_k8s_lifecycle_claim_usage();
DROP TABLE IF EXISTS k8s_lifecycle_claim_usage;

DROP TRIGGER IF EXISTS node_lifecycle_consumption_must_bind ON node_join_tokens;
DROP TRIGGER IF EXISTS node_join_tokens_lifecycle_capture_before_update ON node_join_tokens;
DROP TRIGGER IF EXISTS nodes_lifecycle_token_link_after_insert ON nodes;
DROP TRIGGER IF EXISTS nodes_lifecycle_claim_bind_before_insert ON nodes;

DROP FUNCTION IF EXISTS node_lifecycle_verify_consumption_bound();
DROP FUNCTION IF EXISTS node_lifecycle_link_token_after_insert();
DROP FUNCTION IF EXISTS node_lifecycle_bind_claim_before_insert();
DROP FUNCTION IF EXISTS node_lifecycle_capture_consumption();

DROP TABLE IF EXISTS node_lifecycle_enrollment_authorizations;

DROP INDEX IF EXISTS node_join_tokens_lifecycle_claim_key;

ALTER TABLE node_join_tokens
    DROP CONSTRAINT IF EXISTS node_join_tokens_lifecycle_shape_check,
    DROP CONSTRAINT IF EXISTS node_join_tokens_lifecycle_generation_check,
    DROP COLUMN IF EXISTS lifecycle_aborted_at,
    DROP COLUMN IF EXISTS lifecycle_acknowledged_at,
    DROP COLUMN IF EXISTS lifecycle_token_sealed,
    DROP COLUMN IF EXISTS lifecycle_request_id,
    DROP COLUMN IF EXISTS lifecycle_generation,
    DROP COLUMN IF EXISTS lifecycle_claim;

DROP INDEX IF EXISTS nodes_lifecycle_claim_key;

ALTER TABLE nodes
    DROP COLUMN IF EXISTS lifecycle_claim;
