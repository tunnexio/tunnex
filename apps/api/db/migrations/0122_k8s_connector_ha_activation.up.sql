-- S20.3b: operator-controlled connector HA activation. This migration is
-- additive and dormant: a missing settings/transition row means OFF/legacy.

CREATE TABLE k8s_ha_settings (
    org_id              uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE RESTRICT,
    enabled             boolean NOT NULL DEFAULT false,
    revision            bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    actor_user_id       uuid REFERENCES users (id) ON DELETE RESTRICT,
    actor_system        text,
    cause               text NOT NULL CHECK (octet_length(btrim(cause)) BETWEEN 1 AND 200),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CHECK ((actor_user_id IS NOT NULL AND actor_system IS NULL)
        OR (actor_user_id IS NULL AND actor_system IS NOT NULL)),
    CHECK (actor_system IS NULL OR octet_length(actor_system) BETWEEN 1 AND 100)
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_ha_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE k8s_connector_pool_ha_transitions (
    pool_id                       uuid PRIMARY KEY,
    org_id                        uuid NOT NULL,
    site_id                       uuid NOT NULL,
    cluster_id                    uuid NOT NULL,
    requested_mode                text NOT NULL DEFAULT 'legacy'
                                  CHECK (requested_mode IN ('legacy','fenced_ha')),
    actual_mode                   text NOT NULL DEFAULT 'legacy'
                                  CHECK (actual_mode IN ('legacy','bootstrap_pending','fenced_ha','drain_pending','blocked')),
    active_node_id                uuid NOT NULL,
    promotion_generation          bigint NOT NULL CHECK (promotion_generation > 0),
    membership_epoch              bigint CHECK (membership_epoch >= 0),
    transition_revision           bigint NOT NULL DEFAULT 1 CHECK (transition_revision > 0),
    achieved_authority_revision   bigint CHECK (achieved_authority_revision > 0),
    reason_code                   text NOT NULL DEFAULT 'legacy'
                                  CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    actor_user_id                 uuid REFERENCES users (id) ON DELETE RESTRICT,
    actor_system                  text,
    cause                         text NOT NULL CHECK (octet_length(btrim(cause)) BETWEEN 1 AND 200),
    requested_at                  timestamptz NOT NULL DEFAULT now(),
    achieved_at                   timestamptz,
    created_at                    timestamptz NOT NULL DEFAULT now(),
    updated_at                    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (pool_id, org_id, site_id, cluster_id),
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
        REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id) ON DELETE RESTRICT,
    FOREIGN KEY (active_node_id, org_id, site_id)
        REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT,
    CHECK ((actor_user_id IS NOT NULL AND actor_system IS NULL)
        OR (actor_user_id IS NULL AND actor_system IS NOT NULL)),
    CHECK (actor_system IS NULL OR octet_length(actor_system) BETWEEN 1 AND 100),
    CHECK ((actual_mode IN ('fenced_ha','legacy') AND achieved_at IS NOT NULL)
        OR (actual_mode NOT IN ('fenced_ha','legacy') AND achieved_at IS NULL)),
    CHECK (actual_mode <> 'fenced_ha' OR requested_mode = 'fenced_ha'),
    CHECK (actual_mode <> 'fenced_ha' OR (achieved_authority_revision IS NOT NULL AND membership_epoch IS NOT NULL))
);
CREATE INDEX k8s_connector_pool_ha_transitions_org_mode_idx
    ON k8s_connector_pool_ha_transitions (org_id, actual_mode, pool_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_connector_pool_ha_transitions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- User identities are global, but HA configuration is tenant-scoped. Keep raw
-- and mixed-version writers from attributing a change to another tenant's user.
-- System actors remain first-class for achieved runtime transitions.
CREATE FUNCTION k8s_ha_actor_require_org_membership() RETURNS trigger AS $$
BEGIN
    IF NEW.actor_user_id IS NULL THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM memberships m
        WHERE m.org_id=NEW.org_id AND m.user_id=NEW.actor_user_id
        FOR SHARE
    ) THEN
        RAISE EXCEPTION 'k8s_ha_actor_not_organization_member';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER k8s_ha_settings_actor_before_write
    BEFORE INSERT OR UPDATE ON k8s_ha_settings FOR EACH ROW
    EXECUTE FUNCTION k8s_ha_actor_require_org_membership();
CREATE TRIGGER k8s_connector_pool_ha_transitions_actor_before_write
    BEFORE INSERT OR UPDATE ON k8s_connector_pool_ha_transitions FOR EACH ROW
    EXECUTE FUNCTION k8s_ha_actor_require_org_membership();

CREATE TABLE k8s_base_authority_node_states (
    org_id                    uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    site_id                   uuid NOT NULL,
    node_id                   uuid NOT NULL,
    next_authority_revision   bigint NOT NULL DEFAULT 1 CHECK (next_authority_revision > 0),
    accepted_authority_revision bigint NOT NULL DEFAULT 0 CHECK (accepted_authority_revision >= 0),
    accepted_payload_digest   text CHECK (accepted_payload_digest ~ '^[0-9a-f]{64}$'),
    created_at                timestamptz NOT NULL DEFAULT now(),
    updated_at                timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, node_id),
    FOREIGN KEY (node_id, org_id, site_id)
        REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT,
    CHECK ((accepted_authority_revision = 0 AND accepted_payload_digest IS NULL)
        OR (accepted_authority_revision > 0 AND accepted_payload_digest IS NOT NULL)),
    CHECK (next_authority_revision > accepted_authority_revision)
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_base_authority_node_states
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE k8s_base_authority_deliveries (
    id                    uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id                uuid NOT NULL REFERENCES organizations (id) ON DELETE RESTRICT,
    site_id               uuid NOT NULL,
    node_id               uuid NOT NULL,
    authority_revision    bigint NOT NULL CHECK (authority_revision > 0),
    wire_version          integer NOT NULL CHECK (wire_version = 1),
    base_version          bigint NOT NULL CHECK (base_version > 0),
    base_hash             text NOT NULL CHECK (base_hash ~ '^[0-9a-f]{64}$'),
    payload_digest        text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    payload               jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 131072),
    transition_revision   bigint NOT NULL CHECK (transition_revision > 0),
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, node_id, authority_revision),
    UNIQUE (id, org_id, site_id, node_id),
    CONSTRAINT k8s_base_authority_deliveries_exact_key UNIQUE
        (id, org_id, site_id, node_id, authority_revision, payload_digest, base_version, base_hash),
    FOREIGN KEY (node_id, org_id, site_id)
        REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT,
    CHECK (expires_at > created_at)
);
CREATE INDEX k8s_base_authority_deliveries_node_current_idx
    ON k8s_base_authority_deliveries (org_id, node_id, authority_revision DESC);

CREATE TABLE k8s_base_authority_delivery_pools (
    delivery_id          uuid NOT NULL,
    org_id               uuid NOT NULL,
    site_id              uuid NOT NULL,
    node_id              uuid NOT NULL,
    cluster_id           uuid NOT NULL,
    pool_id              uuid NOT NULL,
    promotion_generation bigint NOT NULL CHECK (promotion_generation > 0),
    kind                 text NOT NULL CHECK (kind IN ('classification','unfence')),
    disposition          text CHECK (disposition IN ('arm_fence','maintain_fence')),
    classification       jsonb,
    classification_digest text,
    PRIMARY KEY (delivery_id, pool_id),
    FOREIGN KEY (delivery_id, org_id, site_id, node_id)
        REFERENCES k8s_base_authority_deliveries (id, org_id, site_id, node_id) ON DELETE RESTRICT,
    FOREIGN KEY (pool_id, org_id, site_id, cluster_id)
        REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id) ON DELETE RESTRICT,
    CHECK ((kind = 'classification' AND disposition IS NOT NULL
            AND jsonb_typeof(classification) = 'object'
            AND octet_length(classification::text) <= 65536
            AND classification_digest ~ '^[0-9a-f]{64}$')
        OR (kind = 'unfence' AND disposition IS NULL
            AND classification IS NULL AND classification_digest IS NULL))
);
CREATE INDEX k8s_base_authority_delivery_pools_scope_idx
    ON k8s_base_authority_delivery_pools (org_id, pool_id, promotion_generation, delivery_id);

CREATE TABLE k8s_base_authority_ack_receipts (
    delivery_id             uuid PRIMARY KEY,
    org_id                  uuid NOT NULL,
    site_id                 uuid NOT NULL,
    node_id                 uuid NOT NULL,
    authority_revision      bigint NOT NULL CHECK (authority_revision > 0),
    payload_digest          text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    applied_base_version    bigint NOT NULL CHECK (applied_base_version > 0),
    applied_base_hash       text NOT NULL CHECK (applied_base_hash ~ '^[0-9a-f]{64}$'),
    agent_applied_at        timestamptz NOT NULL,
    receipt_time            timestamptz NOT NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, node_id, authority_revision),
    CONSTRAINT k8s_base_authority_ack_delivery_exact_fk
        FOREIGN KEY (delivery_id, org_id, site_id, node_id, authority_revision,
                     payload_digest, applied_base_version, applied_base_hash)
        REFERENCES k8s_base_authority_deliveries
                   (id, org_id, site_id, node_id, authority_revision,
                    payload_digest, base_version, base_hash)
        ON DELETE RESTRICT
);
