-- Down-discipline ([7] class): a src_kind='site' row (or any row with src_site_id set) would violate the
-- narrowed CHECK and the dropped column — purge dependent rows FIRST, then reverse the schema.
DELETE FROM policy_rules WHERE src_kind = 'site' OR src_site_id IS NOT NULL;

DROP INDEX IF EXISTS policy_rules_site_site_uniq;
DROP INDEX IF EXISTS policy_rules_site_group_uniq;
DROP INDEX IF EXISTS policy_rules_site_resource_uniq;

-- Restore 0030's two-way src_check (group|user only).
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_check CHECK (
    (src_kind = 'group' AND src_group_id IS NOT NULL AND src_user_id IS NULL)
 OR (src_kind = 'user'  AND src_user_id  IS NOT NULL AND src_group_id IS NULL));

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_kind_check
    CHECK (src_kind IN ('group', 'user'));

ALTER TABLE policy_rules DROP COLUMN src_site_id;
