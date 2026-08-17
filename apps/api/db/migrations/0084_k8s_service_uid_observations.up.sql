-- S10.3 P2: durable Kubernetes Service UID observations. This migration is
-- intentionally reserved after consolidated P1 0079 connector pools, P2 0080
-- Service-port exposures, P2 0081 ownership delivery, P1 0082 handoff
-- operations, and P1 0083 health. It does not copy P1 migrations.
--
-- P1 0079 owns nodes_id_org_site_key and k8s_clusters_id_org_site_key. 0084
-- reuses those composite keys; it must not add duplicate unique indexes. The
-- 0084-owned connector FK below closes 0078's single-column binding gap so a
-- raw selected connector cannot cross org/site ownership.

ALTER TABLE k8s_clusters
    ADD CONSTRAINT k8s_clusters_connector_node_org_site_k8s_uid_observation_fk
    FOREIGN KEY (connector_node_id, org_id, site_id)
    REFERENCES nodes (id, org_id, site_id) ON DELETE SET NULL (connector_node_id);

-- Replay is intentionally connector-scoped: after a handover, a new selected
-- connector starts with its own sequence and exact-retry receipt window.
CREATE TABLE k8s_service_uid_observation_replay_states (
    id                uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id            uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id           uuid        NOT NULL,
    cluster_id        uuid        NOT NULL,
    connector_node_id uuid        NOT NULL,
    scope_identity    text        NOT NULL,
    sequence          bigint      NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    digest            text        NOT NULL DEFAULT '' CHECK (digest = '' OR digest ~ '^[0-9a-f]{64}$'),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, site_id, cluster_id, connector_node_id),
    UNIQUE (id, org_id),
    CHECK ((sequence = 0 AND digest = '') OR (sequence > 0 AND digest ~ '^[0-9a-f]{64}$')),
    FOREIGN KEY (cluster_id, org_id, site_id)
        REFERENCES k8s_clusters (id, org_id, site_id) ON DELETE CASCADE,
    FOREIGN KEY (connector_node_id, org_id, site_id)
        REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT
);
CREATE INDEX k8s_service_uid_observation_replay_states_org_idx
    ON k8s_service_uid_observation_replay_states (org_id, cluster_id, connector_node_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_service_uid_observation_replay_states
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The selected connector is mutable, so the database enforces it on replay
-- state creation/mutation. Historical replay rows remain tied to their former
-- connector; they are never transferred during a handover.
CREATE FUNCTION k8s_service_uid_observation_require_selected_connector() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM k8s_clusters c
        WHERE c.id = NEW.cluster_id
          AND c.org_id = NEW.org_id
          AND c.site_id = NEW.site_id
          AND c.connector_node_id = NEW.connector_node_id
    ) THEN
        RAISE EXCEPTION 'Kubernetes Service UID observation connector is not selected for cluster';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_service_uid_observation_require_selected_connector_before_write
    BEFORE INSERT OR UPDATE OF org_id, site_id, cluster_id, connector_node_id
    ON k8s_service_uid_observation_replay_states
    FOR EACH ROW EXECUTE FUNCTION k8s_service_uid_observation_require_selected_connector();

-- Incarnation authority is cluster-scoped, not connector-scoped. The store
-- locks this row in the same transaction as the current replay state, so a
-- handover gets fresh replay sequencing but cannot revive a retired UID.
CREATE TABLE k8s_service_uid_observation_ledgers (
    id             uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id         uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id        uuid        NOT NULL,
    cluster_id     uuid        NOT NULL,
    scope_identity text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, site_id, cluster_id),
    UNIQUE (id, org_id),
    FOREIGN KEY (cluster_id, org_id, site_id)
        REFERENCES k8s_clusters (id, org_id, site_id) ON DELETE CASCADE
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_service_uid_observation_ledgers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Receipts are a bounded exact-retry window per selected connector. Once a
-- receipt is pruned, that connector's durable high-watermark still rejects the
-- old retry as stale; pruning can never revive a cluster incarnation.
CREATE TABLE k8s_service_uid_observation_receipts (
    id           uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id       uuid        NOT NULL,
    replay_state_id uuid     NOT NULL,
    sequence     bigint      NOT NULL CHECK (sequence > 0),
    digest       text        NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    receipt_time timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (replay_state_id, sequence),
    FOREIGN KEY (replay_state_id, org_id)
        REFERENCES k8s_service_uid_observation_replay_states (id, org_id) ON DELETE CASCADE
);
CREATE INDEX k8s_service_uid_observation_receipts_state_idx
    ON k8s_service_uid_observation_receipts (replay_state_id, sequence DESC);

CREATE TABLE k8s_service_uid_observation_current (
    ledger_id       uuid        NOT NULL,
    org_id          uuid        NOT NULL,
    namespace       text        NOT NULL CHECK (namespace ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND octet_length(namespace) BETWEEN 1 AND 63),
    service         text        NOT NULL CHECK (service ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND octet_length(service) BETWEEN 1 AND 63),
    uid             text        NOT NULL CHECK (octet_length(uid) BETWEEN 1 AND 253 AND uid !~ '[[:cntrl:]]'),
    state           text        NOT NULL CHECK (state IN ('live', 'deleted')),
    replay_sequence bigint      NOT NULL CHECK (replay_sequence > 0),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ledger_id, namespace, service),
    FOREIGN KEY (ledger_id, org_id)
        REFERENCES k8s_service_uid_observation_ledgers (id, org_id) ON DELETE CASCADE
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_service_uid_observation_current
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Retired incarnations are deliberately cluster-wide and never pruned: a
-- future selected connector must reject an old UID just as its predecessor did.
CREATE TABLE k8s_service_uid_observation_retired (
    ledger_id                uuid        NOT NULL,
    org_id                   uuid        NOT NULL,
    namespace                text        NOT NULL CHECK (namespace ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND octet_length(namespace) BETWEEN 1 AND 63),
    service                  text        NOT NULL CHECK (service ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND octet_length(service) BETWEEN 1 AND 63),
    uid                      text        NOT NULL CHECK (octet_length(uid) BETWEEN 1 AND 253 AND uid !~ '[[:cntrl:]]'),
    retired_replay_sequence  bigint      NOT NULL CHECK (retired_replay_sequence > 0),
    retired_at               timestamptz NOT NULL,
    PRIMARY KEY (ledger_id, namespace, service, uid),
    FOREIGN KEY (ledger_id, org_id)
        REFERENCES k8s_service_uid_observation_ledgers (id, org_id) ON DELETE CASCADE
);
CREATE INDEX k8s_service_uid_observation_retired_ledger_idx
    ON k8s_service_uid_observation_retired (ledger_id, retired_replay_sequence DESC);

-- Keep the cluster-wide non-revival history bounded even if a future SQL
-- writer bypasses Go. Existing tombstones remain idempotently writable at
-- capacity; only a new UID is refused, never pruned.
CREATE FUNCTION k8s_service_uid_observation_bound_retired() RETURNS trigger AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM k8s_service_uid_observation_retired
        WHERE ledger_id=NEW.ledger_id AND namespace=NEW.namespace
          AND service=NEW.service AND uid=NEW.uid
    ) THEN
        RETURN NEW;
    END IF;
    IF (SELECT count(*) FROM k8s_service_uid_observation_retired WHERE ledger_id=NEW.ledger_id) >= 1024 THEN
        RAISE EXCEPTION 'Kubernetes Service UID observation retired-incarnation capacity reached';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_service_uid_observation_bound_retired_before_insert
    BEFORE INSERT ON k8s_service_uid_observation_retired
    FOR EACH ROW EXECUTE FUNCTION k8s_service_uid_observation_bound_retired();
