-- Disabled, never-delivered storage only. No API, capability, authorization,
-- delivery, acknowledgement or runtime activation is implemented by this schema.
CREATE TABLE ipsec_org_settings (
    org_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE RESTRICT,
    enabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ipsec_connections (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 255),
    site_id uuid,
    gateway_node_id uuid,
    historical_site_id uuid NOT NULL,
    historical_gateway_node_id uuid NOT NULL,
    desired_revision bigint NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    desired_intent text NOT NULL DEFAULT 'disabled' CHECK (desired_intent IN ('disabled', 'deleted')),
    deleted_at timestamptz,
    finalized_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id),
    FOREIGN KEY (site_id, org_id) REFERENCES sites(id, org_id) ON DELETE RESTRICT,
    -- Reuse the existing composite key. This FK serializes create against raw
    -- gateway unbind/reassignment/deletion without blocking revocation.
    FOREIGN KEY (gateway_node_id, org_id, site_id) REFERENCES nodes(id, org_id, site_id) ON DELETE RESTRICT,
    CHECK (
        (desired_intent = 'disabled' AND site_id IS NOT NULL AND gateway_node_id IS NOT NULL
         AND site_id = historical_site_id AND gateway_node_id = historical_gateway_node_id
         AND deleted_at IS NULL AND finalized_at IS NULL)
        OR
        (desired_intent = 'deleted' AND site_id IS NULL AND gateway_node_id IS NULL
         AND deleted_at IS NOT NULL AND finalized_at IS NOT NULL)
    )
);
CREATE INDEX ipsec_connections_org_idx ON ipsec_connections(org_id);
CREATE INDEX ipsec_connections_site_idx ON ipsec_connections(site_id) WHERE site_id IS NOT NULL;
CREATE INDEX ipsec_connections_gateway_idx ON ipsec_connections(gateway_node_id) WHERE gateway_node_id IS NOT NULL;

CREATE TABLE ipsec_tunnels (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    slot smallint NOT NULL CHECK (slot IN (1, 2)),
    secret_revision bigint NOT NULL DEFAULT 1 CHECK (secret_revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (connection_id, slot),
    UNIQUE (id, org_id, connection_id, secret_revision),
    FOREIGN KEY (connection_id, org_id) REFERENCES ipsec_connections(id, org_id) ON DELETE RESTRICT
);
CREATE TABLE ipsec_tunnel_secrets (
    tunnel_id uuid PRIMARY KEY,
    org_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    secret_revision bigint NOT NULL CHECK (secret_revision > 0),
    sealed_psk text NOT NULL CHECK (octet_length(sealed_psk) BETWEEN 1 AND 16384),
    FOREIGN KEY (tunnel_id, org_id, connection_id, secret_revision)
        REFERENCES ipsec_tunnels(id, org_id, connection_id, secret_revision) ON DELETE RESTRICT
);

-- Organization row exists before a settings row. Its lock closes the missing-
-- setting and concurrent soft-delete races. Service transactions must acquire
-- org -> setting -> site -> gateway -> connection -> tunnel locks in that order.
CREATE FUNCTION ipsec_require_live_org(p_org_id uuid) RETURNS void AS $$
DECLARE v_deleted_at timestamptz;
BEGIN
    SELECT deleted_at INTO v_deleted_at FROM organizations WHERE id = p_org_id FOR UPDATE;
    IF NOT FOUND OR v_deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'IPsec organization unavailable' USING ERRCODE = '23514';
    END IF;
    -- A lock alone does not invalidate an older REPEATABLE READ snapshot.
    -- Version the organization so a concurrent soft-delete with that snapshot
    -- fails serialization rather than missing a newly committed connection.
    -- The existing setter records this configuration change in updated_at.
    UPDATE organizations SET updated_at = updated_at WHERE id = p_org_id;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION ipsec_setting_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'IPsec setting erasure unavailable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 THEN
            RAISE EXCEPTION 'IPsec initial revision invalid' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR OLD.revision = 9223372036854775807 OR NEW.revision <> OLD.revision + 1 THEN
            RAISE EXCEPTION 'IPsec setting update invalid' USING ERRCODE = '23514';
        END IF;
    END IF;
    PERFORM ipsec_require_live_org(NEW.org_id);
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_setting_before_write BEFORE INSERT OR UPDATE OR DELETE ON ipsec_org_settings
    FOR EACH ROW EXECUTE FUNCTION ipsec_setting_guard();

CREATE FUNCTION ipsec_connection_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'IPsec connection erasure unavailable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.desired_intent <> 'disabled' OR NEW.desired_revision <> 1 THEN
            RAISE EXCEPTION 'IPsec initial state invalid' USING ERRCODE = '23514';
        END IF;
        PERFORM ipsec_require_live_org(NEW.org_id);
    ELSE
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.org_id IS DISTINCT FROM OLD.org_id
           OR NEW.historical_site_id IS DISTINCT FROM OLD.historical_site_id
           OR NEW.historical_gateway_node_id IS DISTINCT FROM OLD.historical_gateway_node_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR OLD.desired_intent = 'deleted'
           OR OLD.desired_revision = 9223372036854775807
           OR NEW.desired_revision <> OLD.desired_revision + 1 THEN
            RAISE EXCEPTION 'IPsec connection update invalid' USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_connection_before_write BEFORE INSERT OR UPDATE OR DELETE ON ipsec_connections
    FOR EACH ROW EXECUTE FUNCTION ipsec_connection_guard();

CREATE FUNCTION ipsec_org_soft_delete_guard() RETURNS trigger AS $$
BEGIN
    IF NEW.deleted_at IS NOT NULL AND EXISTS (
        SELECT 1 FROM ipsec_connections WHERE org_id = OLD.id AND desired_intent <> 'deleted'
    ) THEN
        RAISE EXCEPTION 'IPsec connections prevent organization deletion' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_org_before_soft_delete BEFORE UPDATE OF deleted_at ON organizations
    FOR EACH ROW EXECUTE FUNCTION ipsec_org_soft_delete_guard();

-- Children are immutable until never-delivered finalization. Parent row locking
-- serializes cardinality changes, including direct SQL bypassing future services.
CREATE FUNCTION ipsec_child_guard() RETURNS trigger AS $$
DECLARE v_id uuid; v_intent text;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'IPsec tunnel mutation unavailable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN v_id := OLD.connection_id;
    ELSE v_id := NEW.connection_id;
    END IF;
    SELECT desired_intent INTO v_intent FROM ipsec_connections WHERE id = v_id FOR UPDATE;
    IF NOT FOUND OR (TG_OP = 'INSERT' AND v_intent <> 'disabled')
                 OR (TG_OP = 'DELETE' AND v_intent <> 'deleted') THEN
        RAISE EXCEPTION 'IPsec tunnel lifecycle invalid' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_tunnel_before_write BEFORE INSERT OR UPDATE OR DELETE ON ipsec_tunnels
    FOR EACH ROW EXECUTE FUNCTION ipsec_child_guard();
CREATE TRIGGER ipsec_secret_before_write BEFORE INSERT OR UPDATE OR DELETE ON ipsec_tunnel_secrets
    FOR EACH ROW EXECUTE FUNCTION ipsec_child_guard();

CREATE FUNCTION ipsec_verify_connection_children() RETURNS trigger AS $$
DECLARE v_id uuid; v_intent text; v_tunnels bigint; v_secrets bigint;
BEGIN
    IF TG_TABLE_NAME = 'ipsec_connections' THEN v_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN v_id := OLD.connection_id;
    ELSE v_id := NEW.connection_id;
    END IF;
    SELECT desired_intent INTO v_intent FROM ipsec_connections WHERE id = v_id FOR UPDATE;
    SELECT count(*) INTO v_tunnels FROM ipsec_tunnels WHERE connection_id = v_id;
    SELECT count(*) INTO v_secrets FROM ipsec_tunnel_secrets WHERE connection_id = v_id;
    IF v_intent IS NULL OR (v_intent = 'disabled' AND (v_tunnels <> 2 OR v_secrets <> 2))
       OR (v_intent = 'deleted' AND (v_tunnels <> 0 OR v_secrets <> 0)) THEN
        RAISE EXCEPTION 'IPsec connection children incomplete' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER ipsec_connection_children AFTER INSERT OR UPDATE ON ipsec_connections
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_verify_connection_children();
CREATE CONSTRAINT TRIGGER ipsec_tunnel_children AFTER INSERT OR UPDATE OR DELETE ON ipsec_tunnels
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_verify_connection_children();
CREATE CONSTRAINT TRIGGER ipsec_secret_children AFTER INSERT OR UPDATE OR DELETE ON ipsec_tunnel_secrets
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ipsec_verify_connection_children();

CREATE FUNCTION ipsec_refuse_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'IPsec truncation unavailable' USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER ipsec_setting_before_truncate BEFORE TRUNCATE ON ipsec_org_settings
    FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();
CREATE TRIGGER ipsec_connection_before_truncate BEFORE TRUNCATE ON ipsec_connections
    FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();
CREATE TRIGGER ipsec_tunnel_before_truncate BEFORE TRUNCATE ON ipsec_tunnels
    FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();
CREATE TRIGGER ipsec_secret_before_truncate BEFORE TRUNCATE ON ipsec_tunnel_secrets
    FOR EACH STATEMENT EXECUTE FUNCTION ipsec_refuse_truncate();
