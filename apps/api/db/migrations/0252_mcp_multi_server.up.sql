-- AI-UX-1: an agent can have several MCP servers.
--
-- Each profile gets a short name that is the path the server is reached at:
-- http://127.0.0.1:17100/<server_name> on the agent host and /mcp/<server_name>
-- on the gateway listener. Lower-case letters, digits and hyphens, at most 63
-- characters, unique among an organization's profiles that are not archived.
-- "mcp" is reserved: it is the path every existing client already uses for the
-- first server.

-- The name a profile gets when the caller does not choose one.
CREATE FUNCTION agent_mcp_server_slug(p_name text) RETURNS text AS $$
DECLARE
    slug text;
BEGIN
    slug := btrim(regexp_replace(lower(coalesce(p_name, '')), '[^a-z0-9]+', '-', 'g'), '-');
    slug := rtrim(left(slug, 63), '-');
    IF slug = '' THEN
        RETURN 'server';
    END IF;
    IF slug = 'mcp' THEN
        RETURN 'mcp-server';
    END IF;
    RETURN slug;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

ALTER TABLE agent_mcp_profiles
    ADD COLUMN server_name text NOT NULL DEFAULT '';

-- The first free name for a profile: the slug of its display name, then the
-- same with -2, -3 and so on.
CREATE FUNCTION agent_mcp_free_server_name(p_org_id uuid, p_name text, p_self uuid) RETURNS text AS $$
DECLARE
    base      text := agent_mcp_server_slug(p_name);
    candidate text := base;
    n         integer := 1;
    suffix    text;
BEGIN
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM agent_mcp_profiles p
            WHERE p.org_id = p_org_id AND p.archived_at IS NULL
              AND p.server_name = candidate AND p.id <> p_self
        ) THEN
            RETURN candidate;
        END IF;
        n := n + 1;
        suffix := '-' || n::text;
        candidate := left(base, 63 - length(suffix)) || suffix;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Existing profiles, oldest first so the earliest keeps the plain name. An
-- archived profile keeps the plain slug: it is reachable by nobody.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT id, org_id, name, archived_at FROM agent_mcp_profiles
        ORDER BY org_id, created_at, id
    LOOP
        IF r.archived_at IS NULL THEN
            UPDATE agent_mcp_profiles
               SET server_name = agent_mcp_free_server_name(r.org_id, r.name, r.id)
             WHERE id = r.id;
        ELSE
            UPDATE agent_mcp_profiles SET server_name = agent_mcp_server_slug(r.name) WHERE id = r.id;
        END IF;
    END LOOP;
END $$;

ALTER TABLE agent_mcp_profiles
    ADD CONSTRAINT agent_mcp_profiles_server_name_ck
        CHECK (server_name ~ '^[a-z0-9][a-z0-9-]{0,62}$' AND server_name <> 'mcp');

CREATE UNIQUE INDEX agent_mcp_profiles_org_active_server_name_key
    ON agent_mcp_profiles (org_id, server_name)
    WHERE archived_at IS NULL;

-- A control plane that does not send a name (every version before this one)
-- still creates a usable profile: the name is derived here. Creation of names
-- is serialized per organization so two profiles cannot pick the same one.
CREATE FUNCTION agent_mcp_profile_default_server_name() RETURNS trigger AS $$
BEGIN
    IF NEW.server_name IS NULL OR NEW.server_name = '' THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(NEW.org_id::text || ':mcp-server-name', 0));
        NEW.server_name := agent_mcp_free_server_name(NEW.org_id, NEW.name, NEW.id);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER agent_mcp_profile_default_server_name
    BEFORE INSERT ON agent_mcp_profiles
    FOR EACH ROW EXECUTE FUNCTION agent_mcp_profile_default_server_name();

-- One profile per group and one per agent are no longer rules. A group may hold
-- several active assignments and an agent inherits every one of them; "first"
-- is the earliest active assignment (assigned_at, then id). The same profile
-- still cannot be assigned to the same group twice (UNIQUE (profile_id,
-- agent_group_id) from 0108).
DROP TRIGGER agent_mcp_profile_assignment_one_per_agent ON agent_mcp_profile_assignments;
DROP TRIGGER agent_mcp_profile_member_one_per_agent ON agent_group_members;
DROP FUNCTION agent_mcp_profile_one_per_agent();
DROP INDEX agent_mcp_profile_one_active_group;
