-- Down [7] discipline (S7.5.4): PURGE dst_kind='site' rows BEFORE restoring the 2-kind CHECKs — a
-- site rule has dst_resource_id/dst_group_id NULL, so the restored exactly-one CHECK would abort on it.
-- These rows have no representation in the pre-Slice-3 model, so a rollback drops them (like the 0030
-- per-user purge). Tested up->down->up with a populated site-dst rule.
DELETE FROM policy_rules WHERE dst_kind = 'site';

DROP INDEX IF EXISTS policy_rules_user_site_uniq;
DROP INDEX IF EXISTS policy_rules_group_site_uniq;

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind = 'resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL)
 OR (dst_kind = 'group'    AND dst_group_id    IS NOT NULL AND dst_resource_id IS NULL));

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource', 'group'));

ALTER TABLE policy_rules DROP COLUMN dst_site_id;
