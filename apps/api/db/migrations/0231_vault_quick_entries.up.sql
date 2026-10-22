-- Quick Copy persists a creator-private password before metadata is known.
-- Existing credentials retain their configured state and all encrypted history.
ALTER TABLE vault_entries ADD COLUMN configured boolean NOT NULL DEFAULT true;
ALTER TABLE vault_entries DROP CONSTRAINT vault_entries_title_check;
ALTER TABLE vault_entries DROP CONSTRAINT vault_entries_check;
ALTER TABLE vault_entries ADD CONSTRAINT vault_entries_title_check CHECK (
    (configured AND length(btrim(title)) BETWEEN 1 AND 160)
    OR (NOT configured AND title = '')
);
ALTER TABLE vault_entries ADD CONSTRAINT vault_entries_service_state_check CHECK (
    (NOT configured AND service_id IS NULL AND service_name = '')
    OR (configured AND ((service_id IS NOT NULL AND service_name = '')
        OR (service_id IS NULL AND length(btrim(service_name)) BETWEEN 1 AND 120)))
);
ALTER TABLE vault_entries ADD CONSTRAINT vault_entries_unconfigured_check CHECK (
    configured OR (kind = 'password' AND visibility = 'personal' AND username = ''
        AND subject_kind IS NULL AND subject_id IS NULL AND current_version = 1)
);

-- A deleted entry leaves an idempotency tombstone. A delayed Copy retry must not
-- recreate a password after its owner deliberately removed it. Store no secret
-- or unkeyed password digest here; exact replay checks the bound first version.
CREATE TABLE vault_quick_requests (
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    request_id uuid NOT NULL,
    entry_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, owner_user_id, request_id),
    FOREIGN KEY (org_id, entry_id) REFERENCES vault_entries(org_id, id)
        ON DELETE SET NULL (entry_id)
);
