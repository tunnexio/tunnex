ALTER TABLE user_groups DROP CONSTRAINT user_groups_idp_provider_check;
ALTER TABLE user_groups ADD CONSTRAINT user_groups_idp_provider_check CHECK (idp_provider IS NULL OR idp_provider IN ('microsoft','google','okta'));
ALTER TABLE idp_sync_configs DROP CONSTRAINT idp_sync_configs_provider_check;
ALTER TABLE idp_sync_configs ADD CONSTRAINT idp_sync_configs_provider_check CHECK (provider IN ('microsoft','google','okta'));
ALTER TABLE idp_sync_configs ADD COLUMN okta_org_url text;
ALTER TABLE idp_sync_configs ADD COLUMN sso_connection_id uuid;
ALTER TABLE idp_sync_configs ADD CONSTRAINT idp_sync_connection_org_fk FOREIGN KEY (org_id,sso_connection_id) REFERENCES sso_connections(org_id,id) ON DELETE RESTRICT;
ALTER TABLE idp_sync_configs ADD CONSTRAINT idp_sync_okta_shape CHECK ((provider='okta' AND okta_org_url IS NOT NULL AND sso_connection_id IS NOT NULL) OR (provider<>'okta' AND okta_org_url IS NULL AND sso_connection_id IS NULL));
ALTER TABLE sso_connection_identities ADD COLUMN directory_imported boolean NOT NULL DEFAULT false;
