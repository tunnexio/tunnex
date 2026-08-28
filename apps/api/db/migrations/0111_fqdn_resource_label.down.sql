-- Do not silently discard operator notes during an expand/contract rollback.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM fqdn_resources WHERE label IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back 0111: FQDN resource labels exist';
    END IF;
END $$;

ALTER TABLE fqdn_resources DROP COLUMN label;
