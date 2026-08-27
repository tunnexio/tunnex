-- S21 D11: a selected Site/Gateway is not itself a DNS resolver.  The
-- tenant-owned resolver context records the exact private DNS endpoints the
-- selected gateway may query.  Endpoint configuration is versioned so a
-- Gateway DNS RPC and its resulting answer generation can name the immutable
-- configuration snapshot it used.  No host, public, or control-plane resolver
-- is an implicit alternative.

CREATE TABLE fqdn_resolver_context_configs (
    id          uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id     uuid NOT NULL,
    gateway_id  uuid NOT NULL,
    version     bigint NOT NULL CHECK (version > 0),
    state       text NOT NULL CHECK (state IN ('active', 'retired')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    retired_at  timestamptz NULL,
    created_by  uuid NULL REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (id, org_id),
    UNIQUE (org_id, site_id, gateway_id, version),
    FOREIGN KEY (org_id, gateway_id) REFERENCES nodes(org_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE RESTRICT,
    CHECK ((state = 'active' AND retired_at IS NULL) OR (state = 'retired' AND retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX fqdn_resolver_context_configs_one_active
    ON fqdn_resolver_context_configs (org_id, site_id, gateway_id)
    WHERE state = 'active';
CREATE INDEX fqdn_resolver_context_configs_lookup
    ON fqdn_resolver_context_configs (org_id, site_id, gateway_id, version DESC);

-- An endpoint is a DNS server address, not a hostname.  This keeps the
-- request binding unambiguous and forbids a recursive host lookup before DNS
-- resolution starts.  UDP and TCP are explicit and may coexist in one config.
CREATE TABLE fqdn_resolver_context_endpoints (
    config_id   uuid NOT NULL,
    org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ordinal     smallint NOT NULL CHECK (ordinal >= 0 AND ordinal < 8),
    address     inet NOT NULL,
    port        integer NOT NULL DEFAULT 53 CHECK (port BETWEEN 1 AND 65535),
    transport   text NOT NULL CHECK (transport IN ('udp', 'tcp')),
    PRIMARY KEY (config_id, ordinal),
    FOREIGN KEY (config_id, org_id)
        REFERENCES fqdn_resolver_context_configs(id, org_id) ON DELETE RESTRICT,
    CHECK ((family(address) = 4 AND masklen(address) = 32) OR (family(address) = 6 AND masklen(address) = 128)),
    UNIQUE (config_id, address, port, transport)
);

CREATE FUNCTION fqdn_resolver_config_require_endpoint() RETURNS trigger AS $$
BEGIN
    IF NEW.state = 'active' AND NOT EXISTS (
        SELECT 1 FROM fqdn_resolver_context_endpoints e
        WHERE e.config_id = NEW.id AND e.org_id = NEW.org_id
    ) THEN
        RAISE EXCEPTION 'an active FQDN resolver configuration requires at least one endpoint';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fqdn_resolver_config_before_activate
    BEFORE UPDATE OF state ON fqdn_resolver_context_configs
    FOR EACH ROW EXECUTE FUNCTION fqdn_resolver_config_require_endpoint();

-- Configuration must target the same tenant-selected active gateway/site pair
-- as FQDN resources and generations.  Database enforcement prevents a crafted
-- management request from borrowing another tenant's resolver endpoint.
CREATE FUNCTION fqdn_resolver_config_context_is_selected() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM nodes n
        WHERE n.id = NEW.gateway_id
          AND n.org_id = NEW.org_id
          AND n.site_id = NEW.site_id
          AND n.status = 'active'
    ) THEN
        RAISE EXCEPTION 'FQDN resolver configuration requires an active gateway in the selected site and organization';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fqdn_resolver_config_context_before_write
    BEFORE INSERT OR UPDATE OF org_id, site_id, gateway_id
    ON fqdn_resolver_context_configs
    FOR EACH ROW EXECUTE FUNCTION fqdn_resolver_config_context_is_selected();

-- A published answer generation records exactly which resolver configuration
-- was used.  Existing history stays readable; Lane 2 refuses to activate new
-- DNS output without an active configuration snapshot.
ALTER TABLE fqdn_resource_answer_generations
    ADD COLUMN resolver_config_id uuid NULL;
ALTER TABLE fqdn_resource_answer_generations
    ADD CONSTRAINT fqdn_generation_resolver_config_fk
    FOREIGN KEY (resolver_config_id, org_id)
    REFERENCES fqdn_resolver_context_configs(id, org_id) ON DELETE RESTRICT;
CREATE INDEX fqdn_resource_answer_generations_config_idx
    ON fqdn_resource_answer_generations (org_id, resolver_config_id)
    WHERE resolver_config_id IS NOT NULL;

-- Context configuration has history.  A down migration may only run before
-- any configuration or generation snapshot exists; it must never erase
-- resolver provenance after activation.
