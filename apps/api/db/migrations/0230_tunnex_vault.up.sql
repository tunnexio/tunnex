-- Local, identity-bound encrypted credential ledger. Personal records are never
-- administrator-readable merely because the actor administers the organization.
CREATE TABLE vault_services (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id)
);
CREATE UNIQUE INDEX vault_services_org_name ON vault_services(org_id, lower(name));

CREATE TABLE vault_entries (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    service_id uuid,
    service_name text NOT NULL DEFAULT '',
    title text NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 160),
    kind text NOT NULL CHECK (kind IN ('password', 'api_key')),
    username text NOT NULL DEFAULT '' CHECK (length(username) <= 320),
    visibility text NOT NULL CHECK (visibility IN ('personal', 'assigned')),
    owner_user_id uuid NOT NULL REFERENCES users(id),
    subject_kind text CHECK (subject_kind IN ('user', 'group')),
    subject_id uuid,
    current_version integer NOT NULL CHECK (current_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, service_id) REFERENCES vault_services(org_id, id),
    CHECK ((service_id IS NOT NULL AND service_name = '') OR
           (service_id IS NULL AND length(btrim(service_name)) BETWEEN 1 AND 120)),
    CHECK ((visibility = 'personal' AND subject_kind IS NULL AND subject_id IS NULL) OR
           (visibility = 'assigned' AND service_id IS NOT NULL AND subject_kind IS NOT NULL AND subject_id IS NOT NULL))
);
CREATE INDEX vault_entries_org_updated ON vault_entries(org_id, updated_at DESC, id DESC);
CREATE INDEX vault_entries_owner ON vault_entries(org_id, owner_user_id) WHERE visibility = 'personal';
CREATE INDEX vault_entries_subject ON vault_entries(org_id, subject_kind, subject_id) WHERE visibility = 'assigned';
CREATE TRIGGER set_updated_at BEFORE UPDATE ON vault_entries
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE vault_versions (
    org_id uuid NOT NULL,
    entry_id uuid NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    sealed_payload text NOT NULL,
    changed_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, entry_id, version),
    FOREIGN KEY (org_id, entry_id) REFERENCES vault_entries(org_id, id) ON DELETE CASCADE
);

-- Updating an existing version would silently rewrite history. Deletion is only
-- through the explicit, authorized whole-entry deletion path in this release.
CREATE FUNCTION vault_version_prevent_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Vault versions cannot be updated';
END;
$$;
CREATE TRIGGER vault_versions_no_update BEFORE UPDATE ON vault_versions
    FOR EACH ROW EXECUTE FUNCTION vault_version_prevent_update();
