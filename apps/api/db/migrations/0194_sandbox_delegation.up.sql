-- Source-only, opt-in delegation. Existing runtime admission remains authoritative.
ALTER TABLE organizations ADD COLUMN sandbox_delegation_enabled boolean NOT NULL DEFAULT false;
CREATE TABLE sandbox_delegations (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 owner_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 machine_id uuid NOT NULL REFERENCES machine_credentials(id) ON DELETE RESTRICT,
 template_id uuid NOT NULL REFERENCES sandbox_templates(id) ON DELETE RESTRICT,
 max_ttl_seconds integer NOT NULL CHECK (max_ttl_seconds BETWEEN 300 AND 900),
 max_active integer NOT NULL CHECK (max_active BETWEEN 1 AND 2),
 maximum_scope jsonb NOT NULL CHECK (jsonb_typeof(maximum_scope)='array'),
 skill_revision_ids uuid[] NOT NULL DEFAULT '{}',
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK (expires_at > created_at)
);
CREATE UNIQUE INDEX sandbox_delegations_active_machine ON sandbox_delegations(machine_id) WHERE revoked_at IS NULL;
CREATE TABLE sandbox_delegated_instances (
 sandbox_id uuid PRIMARY KEY REFERENCES sandboxes(id) ON DELETE CASCADE,
 delegation_id uuid NOT NULL REFERENCES sandbox_delegations(id) ON DELETE RESTRICT
);

-- Shared effective-deny predicate for runtime credentials and reconciliation.
-- Legacy human-created instances have no association and remain unchanged.
CREATE FUNCTION sandbox_delegation_valid(target uuid) RETURNS boolean
LANGUAGE sql VOLATILE AS $$
 SELECT NOT EXISTS (SELECT 1 FROM sandbox_delegated_instances WHERE sandbox_id=target)
 OR EXISTS (
 SELECT 1 FROM sandbox_delegated_instances i
 JOIN sandboxes s ON s.id=i.sandbox_id
 JOIN sandbox_delegations d ON d.id=i.delegation_id AND d.org_id=s.org_id AND d.owner_id=s.creator_id AND d.template_id=s.template_id
 JOIN machine_credentials c ON c.id=d.machine_id AND c.org_id=d.org_id AND c.user_id=d.owner_id AND c.revoked_at IS NULL
 JOIN organizations o ON o.id=d.org_id AND o.deleted_at IS NULL AND o.sandbox_delegation_enabled
 JOIN users u ON u.id=d.owner_id AND u.status='active' AND u.deleted_at IS NULL AND NOT u.must_change_password AND u.email_verified_at IS NOT NULL
 JOIN memberships m ON m.org_id=d.org_id AND m.user_id=d.owner_id AND COALESCE(m.roles,ARRAY[m.role]) && ARRAY['member','admin','owner']::text[]
 WHERE i.sandbox_id=target AND d.revoked_at IS NULL AND d.expires_at>clock_timestamp()
 );
$$;
