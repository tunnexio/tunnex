-- RBAC-1: four human roles (auditor, agents-admin, network-admin, helpdesk), ranked below admin.
-- Widening only: no existing role or role set changes. The role-set trigger keeps its rules; only its
-- rank order and the maximum number of roles a person can hold grow.
ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_role_check
    CHECK (role IN ('owner', 'admin', 'member', 'ai-admin', 'ai-view', 'auditor', 'agents-admin', 'network-admin', 'helpdesk'));
ALTER TABLE invitations DROP CONSTRAINT invitations_role_check;
ALTER TABLE invitations ADD CONSTRAINT invitations_role_check
    CHECK (role IN ('owner', 'admin', 'member', 'ai-admin', 'ai-view', 'auditor', 'agents-admin', 'network-admin', 'helpdesk'));

CREATE OR REPLACE FUNCTION membership_role_set() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    -- Mirrors rbac.NormalizeHumanRoles: the first role in this order is the compatibility primary role.
    rank_order text[] := ARRAY['owner', 'admin', 'network-admin', 'agents-admin', 'auditor', 'helpdesk', 'ai-admin', 'ai-view', 'member'];
BEGIN
    IF TG_OP = 'INSERT' AND NEW.roles IS NULL THEN
        NEW.roles := ARRAY[NEW.role];
    ELSIF TG_OP = 'UPDATE' AND NEW.roles IS NOT DISTINCT FROM OLD.roles AND NEW.role <> OLD.role THEN
        -- Legacy single-role writes replace the old primary and keep others.
        SELECT array_agg(DISTINCT r) INTO NEW.roles
        FROM unnest(array_remove(OLD.roles, OLD.role) || ARRAY[NEW.role]) AS r;
    END IF;
    IF NEW.roles IS NULL OR cardinality(NEW.roles) = 0
       OR cardinality(NEW.roles) > cardinality(rank_order)
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
