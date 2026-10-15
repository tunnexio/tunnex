-- Optional public CNAME completion reuses existing immutable endpoint rows.
CREATE OR REPLACE FUNCTION fqdn_resolver_config_require_endpoint() RETURNS trigger AS $$
BEGIN
 IF NEW.state='active'
  AND NOT EXISTS (SELECT 1 FROM fqdn_resolver_context_endpoints e WHERE e.config_id=NEW.id AND e.org_id=NEW.org_id)
  AND NOT EXISTS (SELECT 1 FROM fqdn_resolver_context_profiles p WHERE p.config_id=NEW.id AND p.org_id=NEW.org_id
    AND (jsonb_array_length(p.static_records)>0 OR EXISTS(SELECT 1 FROM fqdn_resolver_context_profile_endpoints e WHERE e.profile_id=p.id AND e.org_id=p.org_id))) THEN
  RAISE EXCEPTION 'an active FQDN resolver configuration requires resolver endpoints or static records';
 END IF;
 -- Endpoints on static profiles are explicit CNAME target resolvers. No rows or
 -- historical revisions are rewritten; ordinary/private resolver modes are unchanged.
 IF NEW.state='active' AND EXISTS (
  SELECT 1 FROM fqdn_resolver_context_profiles p
  WHERE p.config_id=NEW.id AND p.org_id=NEW.org_id AND jsonb_array_length(p.static_records)>0
   AND ((SELECT count(*) FROM fqdn_resolver_context_profile_endpoints e WHERE e.profile_id=p.id AND e.org_id=p.org_id)>3
    OR (SELECT count(DISTINCT e.address) FROM fqdn_resolver_context_profile_endpoints e WHERE e.profile_id=p.id AND e.org_id=p.org_id)
       <> (SELECT count(*) FROM fqdn_resolver_context_profile_endpoints e WHERE e.profile_id=p.id AND e.org_id=p.org_id)
    OR EXISTS(SELECT 1 FROM fqdn_resolver_context_profile_endpoints e WHERE e.profile_id=p.id AND e.org_id=p.org_id
      AND (family(e.address)<>4 OR masklen(e.address)<>32 OR e.port<>53 OR e.transport NOT IN ('udp','tcp')
       OR e.address <<= ANY(ARRAY['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12',
          '192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24',
          '203.0.113.0/24','224.0.0.0/4','240.0.0.0/4']::inet[]))))
 ) THEN
  RAISE EXCEPTION 'static CNAME endpoints require at most 3 distinct public IPv4 resolvers on UDP/TCP 53';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
