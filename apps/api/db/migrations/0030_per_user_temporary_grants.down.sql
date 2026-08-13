DROP INDEX IF EXISTS policy_rules_user_group_uniq;
DROP INDEX IF EXISTS policy_rules_user_resource_uniq;
DROP INDEX IF EXISTS policy_rules_group_group_uniq;
DROP INDEX IF EXISTS policy_rules_group_resource_uniq;
CREATE UNIQUE INDEX policy_rules_resource_uniq ON policy_rules (org_id, src_group_id, dst_resource_id)
    WHERE dst_kind = 'resource';
CREATE UNIQUE INDEX policy_rules_group_uniq ON policy_rules (org_id, src_group_id, dst_group_id)
    WHERE dst_kind = 'group';

DROP INDEX IF EXISTS policy_rules_expires_idx;
ALTER TABLE policy_rules DROP COLUMN expires_at;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_check;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_user_fk;
-- Purge per-USER grants BEFORE restoring src_group_id NOT NULL — a user-subject rule has
-- src_group_id NULL, so the SET NOT NULL would abort ([7]). These rows have no representation
-- in the pre-S7.5.4 group-only model, so a rollback drops them (the up migration only ever
-- back-filled existing rows to 'group'; there is no group equivalent to preserve).
DELETE FROM policy_rules WHERE src_kind = 'user';
ALTER TABLE policy_rules DROP COLUMN src_user_id;
ALTER TABLE policy_rules ALTER COLUMN src_group_id SET NOT NULL;
ALTER TABLE policy_rules DROP COLUMN src_kind;
