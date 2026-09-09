-- Refuse a lossy rollback while AI-role invitation history is present.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM invitations WHERE role IN ('ai-admin', 'ai-view')) THEN
        RAISE EXCEPTION 'cannot roll back invitation roles while AI-role invitations exist';
    END IF;
END $$;
ALTER TABLE invitations DROP CONSTRAINT invitations_role_check;
ALTER TABLE invitations ADD CONSTRAINT invitations_role_check
    CHECK (role IN ('owner', 'admin', 'member'));
