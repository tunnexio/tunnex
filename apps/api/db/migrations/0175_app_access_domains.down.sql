-- Older binaries cannot honor saved browser address authority.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM app_access_domain_settings) THEN
        RAISE EXCEPTION 'App Access domain settings are retained; use a compatible binary or a verified pre-upgrade backup';
    END IF;
END $$;
DROP TRIGGER app_access_reject_portal_hostname ON app_access_hostnames;
DROP FUNCTION app_access_reject_portal_hostname();
DROP TABLE app_access_domain_settings;
