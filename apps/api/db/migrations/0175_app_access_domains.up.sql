-- Installation-wide address authority. An absent row preserves environment defaults.
CREATE TABLE app_access_domain_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version bigint NOT NULL CHECK (version > 0),
    portal_url text NOT NULL CHECK (length(portal_url) BETWEEN 1 AND 2048),
    app_base_domain text NOT NULL CHECK (length(app_base_domain) BETWEEN 1 AND 253),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON app_access_domain_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Reserve the portal boundary against concurrent/future app hostname claims.
CREATE FUNCTION app_access_reject_portal_hostname() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM app_access_domain_settings WHERE
        NEW.hostname = substring(portal_url from '^https://([^:/]+)')) THEN
        RAISE EXCEPTION 'portal hostname cannot be reserved for an application' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER app_access_reject_portal_hostname BEFORE INSERT OR UPDATE ON app_access_hostnames
    FOR EACH ROW EXECUTE FUNCTION app_access_reject_portal_hostname();
