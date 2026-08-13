DROP INDEX IF EXISTS policy_rules_src_device_id_idx;
ALTER TABLE policy_rules DROP COLUMN IF EXISTS src_device_id;
