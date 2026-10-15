-- Static DNS and optional LAN exposure share the existing immutable, tenant-owned profile revision.
ALTER TABLE fqdn_resolver_context_profiles
 ADD COLUMN static_records jsonb NOT NULL DEFAULT '[]'::jsonb,
 ADD COLUMN lan_listener jsonb NULL,
 ADD CONSTRAINT fqdn_static_records_array CHECK (jsonb_typeof(static_records)='array' AND jsonb_array_length(static_records)<=128),
 ADD CONSTRAINT fqdn_static_records_profile CHECK (jsonb_array_length(static_records)=0 OR (NOT legacy_default AND ipsec_connection_id IS NULL)),
 ADD CONSTRAINT fqdn_lan_listener_object CHECK (lan_listener IS NULL OR (jsonb_typeof(lan_listener)='object' AND NOT legacy_default));

CREATE OR REPLACE FUNCTION fqdn_resolver_config_require_endpoint() RETURNS trigger AS $$
BEGIN
 IF NEW.state='active'
  AND NOT EXISTS (SELECT 1 FROM fqdn_resolver_context_endpoints e WHERE e.config_id=NEW.id AND e.org_id=NEW.org_id)
  AND NOT EXISTS (SELECT 1 FROM fqdn_resolver_context_profiles p WHERE p.config_id=NEW.id AND p.org_id=NEW.org_id
    AND (jsonb_array_length(p.static_records)>0 OR EXISTS(SELECT 1 FROM fqdn_resolver_context_profile_endpoints e WHERE e.profile_id=p.id AND e.org_id=p.org_id))) THEN
  RAISE EXCEPTION 'an active FQDN resolver configuration requires resolver endpoints or static records';
 END IF;
 IF NEW.state='active' AND EXISTS (SELECT 1 FROM fqdn_resolver_context_profiles p WHERE p.config_id=NEW.id AND p.org_id=NEW.org_id AND jsonb_array_length(p.static_records)>0
   AND EXISTS (SELECT 1 FROM fqdn_resolver_context_profile_endpoints e WHERE e.profile_id=p.id AND e.org_id=p.org_id)) THEN
  RAISE EXCEPTION 'static DNS profiles cannot also declare upstream endpoints';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
