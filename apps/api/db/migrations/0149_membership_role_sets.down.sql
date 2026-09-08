-- Refuse a lossy downgrade. Remove AI roles and reduce role sets through the
-- membership API before rolling back this migration.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM memberships WHERE cardinality(roles) <> 1 OR role NOT IN ('owner','admin','member')) THEN
        RAISE EXCEPTION 'reduce memberships to one legacy role before downgrade';
    END IF;
END $$;
DROP TRIGGER membership_role_set ON memberships;
DROP FUNCTION membership_role_set();
ALTER TABLE memberships DROP COLUMN roles;
ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_role_check CHECK (role IN ('owner','admin','member'));
