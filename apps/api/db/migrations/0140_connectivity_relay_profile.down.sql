DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM connectivity_profiles WHERE enabled OR secret_sealed IS NOT NULL) THEN
        RAISE EXCEPTION 'configured relay profiles exist; clear before rollback';
    END IF;
END $$;
ALTER TABLE connectivity_profiles DROP COLUMN revision;
ALTER TABLE connectivity_profiles DROP COLUMN secret_sealed;
ALTER TABLE connectivity_profiles DROP COLUMN relay_url;
