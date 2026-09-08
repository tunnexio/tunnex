-- Existing memberships retain their role. The compatibility role is always
-- derived from the full set, including when older callers change only role.
ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_role_check
    CHECK (role IN ('owner', 'admin', 'member', 'ai-admin', 'ai-view'));
ALTER TABLE memberships ADD COLUMN roles text[];
UPDATE memberships SET roles = ARRAY[role];

CREATE FUNCTION membership_role_set() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE TRIGGER membership_role_set BEFORE INSERT OR UPDATE OF role, roles ON memberships
    FOR EACH ROW EXECUTE FUNCTION membership_role_set();
-- Leave the additive column nullable for the rolling-upgrade contract.
-- The trigger rejects null role sets and fills them for legacy INSERTs;
-- existing rows were backfilled above. A schema-level NOT NULL contract can
-- follow after all writers use role sets.
