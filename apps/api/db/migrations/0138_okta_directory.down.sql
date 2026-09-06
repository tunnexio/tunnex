-- Refuse rollback while directory-owned accounts/configurations exist. Never silently
-- discard identity ownership or turn a managed connection back into unrestricted JIT.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM idp_sync_configs WHERE provider='okta') OR EXISTS(SELECT 1 FROM sso_connection_identities WHERE directory_imported) THEN
  RAISE EXCEPTION 'Okta directory ownership exists; migrate it before rollback';
 END IF;
END $$;
ALTER TABLE sso_connection_identities DROP COLUMN directory_imported;
ALTER TABLE idp_sync_configs DROP CONSTRAINT idp_sync_okta_shape;
ALTER TABLE idp_sync_configs DROP CONSTRAINT idp_sync_connection_org_fk;
ALTER TABLE idp_sync_configs DROP COLUMN sso_connection_id;
ALTER TABLE idp_sync_configs DROP COLUMN okta_org_url;
ALTER TABLE idp_sync_configs DROP CONSTRAINT idp_sync_configs_provider_check;
ALTER TABLE idp_sync_configs ADD CONSTRAINT idp_sync_configs_provider_check CHECK (provider IN ('microsoft','google'));
ALTER TABLE user_groups DROP CONSTRAINT user_groups_idp_provider_check;
ALTER TABLE user_groups ADD CONSTRAINT user_groups_idp_provider_check CHECK (idp_provider IS NULL OR idp_provider IN ('microsoft','google'));
