-- Refuse a lossy rollback: a person or invitation holding an RBAC-1 role would lose it. Change those
-- roles through the Users page (or revoke the invitations) before rolling back.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM memberships
               WHERE role IN ('auditor', 'agents-admin', 'network-admin', 'helpdesk')
                  OR roles && ARRAY['auditor', 'agents-admin', 'network-admin', 'helpdesk']::text[])
       OR EXISTS (SELECT 1 FROM invitations WHERE role IN ('auditor', 'agents-admin', 'network-admin', 'helpdesk')) THEN
        RAISE EXCEPTION 'cannot roll back RBAC-1 roles while a membership or invitation uses auditor, agents-admin, network-admin or helpdesk';
    END IF;
END $$;
CREATE OR REPLACE FUNCTION membership_role_set() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    rank_order text[] := ARRAY['owner', 'admin', 'ai-admin', 'ai-view', 'member'];
BEGIN
    IF TG_OP = 'INSERT' AND NEW.roles IS NULL THEN
        NEW.roles := ARRAY[NEW.role];
    ELSIF TG_OP = 'UPDATE' AND NEW.roles IS NOT DISTINCT FROM OLD.roles AND NEW.role <> OLD.role THEN
        -- Legacy single-role writes replace the old primary and keep others.
        SELECT array_agg(DISTINCT r) INTO NEW.roles
        FROM unnest(array_remove(OLD.roles, OLD.role) || ARRAY[NEW.role]) AS r;
    END IF;
    IF NEW.roles IS NULL OR cardinality(NEW.roles) = 0
       OR cardinality(NEW.roles) > 5
       OR array_position(NEW.roles, NULL) IS NOT NULL
       OR NOT NEW.roles <@ rank_order
       OR cardinality(NEW.roles) <> (SELECT count(DISTINCT r) FROM unnest(NEW.roles) r) THEN
        RAISE EXCEPTION 'invalid membership role set' USING ERRCODE = '23514';
    END IF;
    SELECT array_agg(r ORDER BY array_position(rank_order, r)) INTO NEW.roles FROM unnest(NEW.roles) r;
    NEW.role := NEW.roles[1];
    RETURN NEW;
END;
$$;
ALTER TABLE invitations DROP CONSTRAINT invitations_role_check;
ALTER TABLE invitations ADD CONSTRAINT invitations_role_check
    CHECK (role IN ('owner', 'admin', 'member', 'ai-admin', 'ai-view'));
ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_role_check
    CHECK (role IN ('owner', 'admin', 'member', 'ai-admin', 'ai-view'));
