-- S21 D3-D5/D8: additive persistence only for resolver-owned FQDN answers.
--
-- Existing resources remain static CIDR rows and every pre-0110 reader continues
-- to see precisely that shape.  FQDN resources are an independent entity,
-- deliberately not a CIDR sentinel: old compilers must never turn a hostname
-- into an accidental broad address grant during a rolling upgrade.  A later
-- expand/contract contract migration will unify the rendered inventory and rule
-- destination union after every existing CIDR reader has moved safely.

CREATE TABLE fqdn_resources (
    id                uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name              text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 128),
    fqdn              text NOT NULL CHECK (length(fqdn) BETWEEN 1 AND 253),
    protocol          text NOT NULL DEFAULT 'any' CHECK (protocol IN ('any', 'tcp', 'udp')),
    port_low          integer NULL CHECK (port_low BETWEEN 1 AND 65535),
    port_high         integer NULL CHECK (port_high BETWEEN 1 AND 65535),
    resolver_node_id  uuid NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id),
    UNIQUE (org_id, fqdn),
    FOREIGN KEY (org_id, resolver_node_id)
        REFERENCES nodes(org_id, id) ON DELETE RESTRICT,
    CHECK ((protocol = 'any' AND port_low IS NULL AND port_high IS NULL)
        OR (protocol IN ('tcp', 'udp') AND (port_low IS NULL OR port_high IS NULL OR port_low <= port_high)))
);
CREATE UNIQUE INDEX fqdn_resources_org_name_key
    ON fqdn_resources (org_id, lower(name));
CREATE INDEX fqdn_resources_org_resolver_idx
    ON fqdn_resources (org_id, resolver_node_id)
    WHERE resolver_node_id IS NOT NULL;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON fqdn_resources
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- One immutable generation is built against one selected resolver context.
-- `pending` permits a service transaction to insert the complete bounded answer
-- set before it atomically promotes the generation.  Only `active` contributes
-- to future compilation; a failure withdraws it rather than preserving access.
CREATE TABLE fqdn_resource_answer_generations (
    id                uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource_id       uuid NOT NULL,
    generation        bigint NOT NULL CHECK (generation > 0),
    resolver_node_id  uuid NOT NULL,
    state             text NOT NULL CHECK (state IN ('pending', 'active', 'retired', 'withdrawn')),
    effective_ttl     interval NOT NULL CHECK (effective_ttl >= interval '30 seconds' AND effective_ttl <= interval '1 hour'),
    resolved_at       timestamptz NOT NULL,
    last_good_at      timestamptz NULL,
    activated_at      timestamptz NULL,
    ended_at          timestamptz NULL,
    failure_code      text NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id),
    UNIQUE (resource_id, generation),
    FOREIGN KEY (resource_id, org_id)
        REFERENCES fqdn_resources(id, org_id) ON DELETE RESTRICT,
    FOREIGN KEY (org_id, resolver_node_id)
        REFERENCES nodes(org_id, id) ON DELETE RESTRICT,
    CHECK (
        (state = 'pending' AND activated_at IS NULL AND ended_at IS NULL AND failure_code IS NULL)
     OR (state = 'active' AND activated_at IS NOT NULL AND ended_at IS NULL AND failure_code IS NULL)
     OR (state = 'retired' AND activated_at IS NOT NULL AND ended_at IS NOT NULL AND failure_code IS NULL)
     OR (state = 'withdrawn' AND ended_at IS NOT NULL AND failure_code IS NOT NULL)
    )
);
CREATE UNIQUE INDEX fqdn_resource_answer_generations_one_active
    ON fqdn_resource_answer_generations (org_id, resource_id)
    WHERE state = 'active';
CREATE INDEX fqdn_resource_answer_generations_org_resource_state_idx
    ON fqdn_resource_answer_generations (org_id, resource_id, state, generation DESC);

-- Answers are host addresses, never a prefix.  The unique key canonicalizes the
-- set per generation and the trigger below serializes concurrent inserts before
-- enforcing D3's 32-address ceiling.
CREATE TABLE fqdn_resource_generation_answers (
    generation_id  uuid NOT NULL,
    org_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    address        inet NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (generation_id, address),
    FOREIGN KEY (generation_id, org_id)
        REFERENCES fqdn_resource_answer_generations(id, org_id) ON DELETE RESTRICT,
    CHECK (
        (family(address) = 4 AND masklen(address) = 32)
     OR (family(address) = 6 AND masklen(address) = 128)
    )
);
CREATE INDEX fqdn_resource_generation_answers_org_generation_idx
    ON fqdn_resource_generation_answers (org_id, generation_id);

-- A resolver may stage a pending generation, but it can never publish an empty
-- one.  Promotion is therefore pending → answers → active inside one service
-- transaction; a failure exposes neither an active empty set nor a broad fallback.
CREATE FUNCTION fqdn_generation_require_nonempty_active() RETURNS trigger AS $$
BEGIN
    IF NEW.state = 'active' AND NOT EXISTS (
        SELECT 1 FROM fqdn_resource_generation_answers a
        WHERE a.generation_id = NEW.id AND a.org_id = NEW.org_id
    ) THEN
        RAISE EXCEPTION 'an active FQDN answer generation requires at least one answer';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION fqdn_generation_answer_require_mutable() RETURNS trigger AS $$
DECLARE
    answer_count integer;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.generation_id::text, 0));
    IF NOT EXISTS (
        SELECT 1
        FROM fqdn_resource_answer_generations g
        WHERE g.id = NEW.generation_id
          AND g.org_id = NEW.org_id
          AND g.state = 'pending'
    ) THEN
        RAISE EXCEPTION 'FQDN answers may be added only to a pending generation';
    END IF;
    SELECT count(*) INTO answer_count
    FROM fqdn_resource_generation_answers
    WHERE generation_id = NEW.generation_id;
    IF answer_count >= 32 THEN
        RAISE EXCEPTION 'FQDN answer generation exceeds the 32-address limit';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fqdn_generation_answer_before_insert
    BEFORE INSERT ON fqdn_resource_generation_answers
    FOR EACH ROW EXECUTE FUNCTION fqdn_generation_answer_require_mutable();
CREATE TRIGGER fqdn_generation_before_publish
    BEFORE INSERT OR UPDATE OF state ON fqdn_resource_answer_generations
    FOR EACH ROW EXECUTE FUNCTION fqdn_generation_require_nonempty_active();

-- Published answer sets are history: changing one in place would make a
-- generation identity lie.  The future resolver service creates/promotes a new
-- generation and retires or withdraws the old one atomically instead.
CREATE FUNCTION fqdn_generation_answer_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'FQDN generation answers are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fqdn_generation_answer_before_update
    BEFORE UPDATE ON fqdn_resource_generation_answers
    FOR EACH ROW EXECUTE FUNCTION fqdn_generation_answer_immutable();
CREATE TRIGGER fqdn_generation_answer_before_delete
    BEFORE DELETE ON fqdn_resource_generation_answers
    FOR EACH ROW EXECUTE FUNCTION fqdn_generation_answer_immutable();
