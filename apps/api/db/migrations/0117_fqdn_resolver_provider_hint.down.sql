DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM fqdn_resolver_context_configs
        WHERE provider_hint IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'cannot roll back FQDN resolver provider metadata after it has been recorded';
    END IF;
END $$;

ALTER TABLE fqdn_resolver_context_configs
    DROP COLUMN provider_hint;
