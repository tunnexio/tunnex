-- ⚠ The up-migration only EXPANDS, so the down only removes what it added.
UPDATE users SET can_create_orgs = true WHERE cp_admin = true;
ALTER TABLE users DROP COLUMN cp_admin;
