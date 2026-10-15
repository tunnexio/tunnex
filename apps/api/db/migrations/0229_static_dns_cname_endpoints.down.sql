-- Do not discard active resolver configuration to make an old binary appear safe.
DO $$
BEGIN
 IF EXISTS (SELECT 1 FROM fqdn_resolver_context_configs c
  JOIN fqdn_resolver_context_profiles p ON p.config_id=c.id AND p.org_id=c.org_id
  WHERE c.state='active' AND jsonb_array_length(p.static_records)>0
   AND EXISTS(SELECT 1 FROM fqdn_resolver_context_profile_endpoints e WHERE e.profile_id=p.id AND e.org_id=p.org_id)) THEN
  RAISE EXCEPTION 'refusing to roll back 0229 while active static CNAME resolver endpoints exist; replace or retire those profiles first';
 END IF;
END;
$$;

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
