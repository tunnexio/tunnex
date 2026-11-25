-- LS-UX-1 E.3: bind each installation proxy credential to one authority.
-- Every existing credential was issued for App Access (no supported Local
-- Sharing proxy existed before this release), so none gains authority.
ALTER TABLE app_access_proxy_credentials
    ADD COLUMN purpose text NOT NULL DEFAULT 'app_access'
    CONSTRAINT app_access_proxy_credentials_purpose_check CHECK (purpose IN ('app_access','local_sharing'));
