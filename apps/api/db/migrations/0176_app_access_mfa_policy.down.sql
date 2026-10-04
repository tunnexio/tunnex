-- Older binaries cannot enforce retained per-application MFA requirements.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM app_access_applications WHERE require_mfa) THEN
        RAISE EXCEPTION 'App Access MFA policies are retained; disable them explicitly with a compatible binary or restore a verified pre-upgrade backup';
    END IF;
END $$;
ALTER TABLE app_access_applications DROP COLUMN require_mfa;
