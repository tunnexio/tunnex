-- The old schema cannot represent an unconfigured secret. Refuse rollback
-- without changing data; operators must explicitly configure or delete it first.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM vault_entries WHERE NOT configured) THEN
        RAISE EXCEPTION 'Configure or delete unconfigured Vault entries before rollback';
    END IF;
END; $$;
DROP TABLE vault_quick_requests;
ALTER TABLE vault_entries DROP CONSTRAINT vault_entries_unconfigured_check;
ALTER TABLE vault_entries DROP CONSTRAINT vault_entries_service_state_check;
ALTER TABLE vault_entries DROP CONSTRAINT vault_entries_title_check;
ALTER TABLE vault_entries DROP COLUMN configured;
ALTER TABLE vault_entries ADD CONSTRAINT vault_entries_title_check
    CHECK (length(btrim(title)) BETWEEN 1 AND 160);
ALTER TABLE vault_entries ADD CONSTRAINT vault_entries_check CHECK (
    (service_id IS NOT NULL AND service_name = '') OR
    (service_id IS NULL AND length(btrim(service_name)) BETWEEN 1 AND 120)
);
