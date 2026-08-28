-- S21 multi-cloud private DNS routing. Resolver profiles are immutable children
-- of one Site/Gateway resolver-context revision. DNS work selects exactly one
-- profile by the most-specific label-boundary suffix before a gateway request
-- is created; endpoints from different profiles are never mixed or retried.
CREATE TABLE fqdn_resolver_context_profiles (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    config_id       uuid NOT NULL,
    org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ordinal         smallint NOT NULL CHECK (ordinal >= 0 AND ordinal < 16),
    name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 80),
    provider_hint   text NOT NULL CHECK (provider_hint IN ('aws','azure','google_cloud','on_premises')),
    legacy_default  boolean NOT NULL DEFAULT false,
    UNIQUE (id, org_id),
    UNIQUE (id, config_id, org_id),
    UNIQUE (config_id, ordinal),
    FOREIGN KEY (config_id, org_id)
        REFERENCES fqdn_resolver_context_configs(id, org_id) ON DELETE RESTRICT
);

CREATE TABLE fqdn_resolver_context_profile_suffixes (
    profile_id  uuid NOT NULL,
    config_id   uuid NOT NULL,
    org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    suffix      text NOT NULL CHECK (
        suffix = lower(suffix)
        AND suffix = btrim(suffix)
        AND suffix !~ '[*_]'
        AND suffix !~ '^\.'
        AND suffix !~ '\.$'
        AND length(suffix) BETWEEN 1 AND 253
    ),
    PRIMARY KEY (profile_id, suffix),
    FOREIGN KEY (profile_id, config_id, org_id)
        REFERENCES fqdn_resolver_context_profiles(id, config_id, org_id) ON DELETE RESTRICT,
    UNIQUE (config_id, suffix)
);

CREATE TABLE fqdn_resolver_context_profile_endpoints (
    profile_id  uuid NOT NULL,
    org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ordinal     smallint NOT NULL CHECK (ordinal >= 0 AND ordinal < 8),
    address     inet NOT NULL,
    port        integer NOT NULL DEFAULT 53 CHECK (port BETWEEN 1 AND 65535),
    transport   text NOT NULL CHECK (transport IN ('udp','tcp')),
    PRIMARY KEY (profile_id, ordinal),
    FOREIGN KEY (profile_id, org_id)
        REFERENCES fqdn_resolver_context_profiles(id, org_id) ON DELETE RESTRICT,
    CHECK ((family(address)=4 AND masklen(address)=32) OR (family(address)=6 AND masklen(address)=128)),
    UNIQUE (profile_id, address, port, transport)
);

-- Existing flat configurations become an explicit legacy catch-all profile.
-- Reusing config id as profile id gives deterministic provenance and keeps
-- already-created configurations stable across replicas.
INSERT INTO fqdn_resolver_context_profiles
    (id,config_id,org_id,ordinal,name,provider_hint,legacy_default)
SELECT id,id,org_id,0,'Legacy resolver',COALESCE(provider_hint,'on_premises'),true
FROM fqdn_resolver_context_configs;

INSERT INTO fqdn_resolver_context_profile_endpoints
    (profile_id,org_id,ordinal,address,port,transport)
SELECT config_id,org_id,ordinal,address,port,transport
FROM fqdn_resolver_context_endpoints;

-- Selected profile provenance survives mailbox failover and answer-history
-- inspection. Older rows remain readable; new v2 requests always populate it.
ALTER TABLE fqdn_gateway_dns_requests
    ADD COLUMN resolver_profile_id uuid NULL,
    ADD COLUMN resolver_match_suffix text NULL;
ALTER TABLE fqdn_gateway_dns_requests
    ADD CONSTRAINT fqdn_gateway_dns_requests_profile_fk
    FOREIGN KEY (resolver_profile_id,org_id)
    REFERENCES fqdn_resolver_context_profiles(id,org_id) ON DELETE RESTRICT;

ALTER TABLE fqdn_resource_answer_generations
    ADD COLUMN resolver_profile_id uuid NULL,
    ADD COLUMN resolver_match_suffix text NULL;
ALTER TABLE fqdn_resource_answer_generations
    ADD CONSTRAINT fqdn_generation_resolver_profile_fk
    FOREIGN KEY (resolver_profile_id,org_id)
    REFERENCES fqdn_resolver_context_profiles(id,org_id) ON DELETE RESTRICT;
CREATE INDEX fqdn_resource_answer_generations_profile_idx
    ON fqdn_resource_answer_generations(org_id,resolver_profile_id)
    WHERE resolver_profile_id IS NOT NULL;

-- Activation may use legacy flat endpoints or the profile-native endpoint set.
CREATE OR REPLACE FUNCTION fqdn_resolver_config_require_endpoint() RETURNS trigger AS $$
BEGIN
    IF NEW.state='active'
       AND NOT EXISTS (SELECT 1 FROM fqdn_resolver_context_endpoints e WHERE e.config_id=NEW.id AND e.org_id=NEW.org_id)
       AND NOT EXISTS (
           SELECT 1 FROM fqdn_resolver_context_profiles p
           JOIN fqdn_resolver_context_profile_endpoints e ON e.profile_id=p.id AND e.org_id=p.org_id
           WHERE p.config_id=NEW.id AND p.org_id=NEW.org_id
       ) THEN
        RAISE EXCEPTION 'an active FQDN resolver configuration requires at least one profile endpoint';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
