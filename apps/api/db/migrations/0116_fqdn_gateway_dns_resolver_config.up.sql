-- S21 D11: bind every authenticated gateway DNS RPC to one immutable,
-- tenant-owned resolver endpoint configuration. The gateway receives only
-- these literal UDP/TCP endpoints; neither the host resolver nor public DNS
-- can be inferred from a mailbox row.
ALTER TABLE fqdn_gateway_dns_requests
    ADD COLUMN resolver_config_id uuid NULL,
    ADD COLUMN resolver_config_version bigint NULL,
    ADD COLUMN resolver_endpoints jsonb NULL;

ALTER TABLE fqdn_gateway_dns_requests
    ADD CONSTRAINT fqdn_gateway_dns_requests_resolver_config_fk
    FOREIGN KEY (resolver_config_id, org_id)
    REFERENCES fqdn_resolver_context_configs(id, org_id) ON DELETE RESTRICT;

ALTER TABLE fqdn_gateway_dns_requests
    ADD CONSTRAINT fqdn_gateway_dns_requests_resolver_config_complete
    CHECK (
        (resolver_config_id IS NULL AND resolver_config_version IS NULL AND resolver_endpoints IS NULL)
        OR
        (resolver_config_id IS NOT NULL AND resolver_config_version > 0
         AND resolver_endpoints IS NOT NULL AND jsonb_typeof(resolver_endpoints) = 'array'
         AND jsonb_array_length(resolver_endpoints) BETWEEN 1 AND 8)
    );

CREATE INDEX fqdn_gateway_dns_requests_resolver_config_idx
    ON fqdn_gateway_dns_requests(org_id, resolver_config_id)
    WHERE resolver_config_id IS NOT NULL;
