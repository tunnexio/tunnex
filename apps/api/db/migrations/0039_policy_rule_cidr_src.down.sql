-- HONEST down (S8.7 [5]): a src_kind='cidr' rule cannot survive the reverted CHECK (which has no 'cidr'
-- arm), so recreating the checks below would ABORT the rollback on a constraint violation. Roll the FEATURE
-- back → drop the FEATURE's rows first, LOUDLY in the migration log (not a silently wedged down). Re-create
-- the cidr rules if you roll 0039 forward again.
DELETE FROM policy_rules WHERE src_kind = 'cidr';

DROP INDEX policy_rules_cidr_site_uniq;
DROP INDEX policy_rules_cidr_group_uniq;
DROP INDEX policy_rules_cidr_resource_uniq;
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_check CHECK (
    (src_kind = 'group' AND src_group_id IS NOT NULL AND src_user_id IS NULL AND src_site_id IS NULL)
 OR (src_kind = 'user'  AND src_user_id  IS NOT NULL AND src_group_id IS NULL AND src_site_id IS NULL)
 OR (src_kind = 'site'  AND src_site_id  IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL));
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_kind_check CHECK (src_kind IN ('group', 'user', 'site'));
ALTER TABLE policy_rules DROP COLUMN src_cidr;
