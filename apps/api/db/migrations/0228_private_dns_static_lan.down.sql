-- Preserve operator configuration and immutable provenance instead of silently losing it.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM fqdn_resolver_context_profiles WHERE jsonb_array_length(static_records)>0 OR lan_listener IS NOT NULL) THEN
  RAISE EXCEPTION 'refusing rollback: static DNS or LAN listener profile provenance exists';
 END IF;
END $$;
CREATE OR REPLACE FUNCTION fqdn_resolver_config_require_endpoint() RETURNS trigger AS $$
BEGIN
 IF NEW.state='active'
  AND NOT EXISTS (SELECT 1 FROM fqdn_resolver_context_endpoints e WHERE e.config_id=NEW.id AND e.org_id=NEW.org_id)
  AND NOT EXISTS (SELECT 1 FROM fqdn_resolver_context_profiles p JOIN fqdn_resolver_context_profile_endpoints e ON e.profile_id=p.id AND e.org_id=p.org_id WHERE p.config_id=NEW.id AND p.org_id=NEW.org_id) THEN
  RAISE EXCEPTION 'an active FQDN resolver configuration requires at least one profile endpoint';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
ALTER TABLE fqdn_resolver_context_profiles DROP COLUMN lan_listener, DROP COLUMN static_records;
