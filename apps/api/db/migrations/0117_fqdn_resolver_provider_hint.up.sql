-- Provider is operator-supplied presentation metadata for an existing resolver
-- boundary. It never changes endpoint selection, DNS authority, credentials,
-- discovery, or policy compilation.
ALTER TABLE fqdn_resolver_context_configs
    ADD COLUMN provider_hint text NULL
    CHECK (provider_hint IN ('aws', 'azure', 'google_cloud', 'on_premises'));
