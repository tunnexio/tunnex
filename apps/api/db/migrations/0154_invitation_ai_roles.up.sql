ALTER TABLE invitations DROP CONSTRAINT invitations_role_check;
ALTER TABLE invitations ADD CONSTRAINT invitations_role_check
    CHECK (role IN ('owner', 'admin', 'member', 'ai-admin', 'ai-view'));
