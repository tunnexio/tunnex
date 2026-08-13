ALTER TABLE organizations DROP COLUMN IF EXISTS zero_trust_mode;
DROP TABLE IF EXISTS policy_rules;
DROP TABLE IF EXISTS resources;
DROP TABLE IF EXISTS group_members;
DROP TABLE IF EXISTS user_groups;
