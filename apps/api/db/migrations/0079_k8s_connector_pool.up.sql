-- S10.3c: additive connector-pool persistence. The legacy
-- k8s_clusters.connector_node_id remains authoritative for existing clusters;
-- this optional pool reference is only a contract for the next handoff slice.
ALTER TABLE nodes
    ADD CONSTRAINT nodes_id_org_site_key UNIQUE (id, org_id, site_id);

ALTER TABLE k8s_clusters
    ADD CONSTRAINT k8s_clusters_id_org_site_key UNIQUE (id, org_id, site_id);

CREATE TABLE k8s_connector_pools (
    id                 uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id             uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id            uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    cluster_id         uuid NOT NULL,
    preferred_node_id  uuid NOT NULL,
    active_node_id     uuid NOT NULL,
    generation         bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, cluster_id),
    UNIQUE (id, org_id, site_id),
    UNIQUE (id, org_id, site_id, cluster_id),
    FOREIGN KEY (cluster_id, org_id, site_id) REFERENCES k8s_clusters (id, org_id, site_id) ON DELETE CASCADE,
    FOREIGN KEY (preferred_node_id, org_id, site_id) REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT,
    FOREIGN KEY (active_node_id, org_id, site_id) REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT
);

CREATE INDEX k8s_connector_pools_org_idx ON k8s_connector_pools (org_id);
CREATE INDEX k8s_connector_pools_site_idx ON k8s_connector_pools (site_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_connector_pools
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE k8s_connector_pool_members (
    pool_id         uuid NOT NULL,
    org_id          uuid NOT NULL,
    site_id         uuid NOT NULL,
    node_id         uuid NOT NULL,
    admin_priority  int NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (pool_id, node_id),
    UNIQUE (pool_id, org_id, site_id, node_id),
    FOREIGN KEY (pool_id, org_id, site_id) REFERENCES k8s_connector_pools (id, org_id, site_id) ON DELETE CASCADE,
    FOREIGN KEY (node_id, org_id, site_id) REFERENCES nodes (id, org_id, site_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX k8s_connector_pool_members_node_unique
    ON k8s_connector_pool_members (node_id);

CREATE INDEX k8s_connector_pool_members_org_idx ON k8s_connector_pool_members (org_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_connector_pool_members
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Preferred and active are not merely same-scope nodes: they must remain
-- members of THIS pool. The constraints are deferred because CreatePool inserts
-- the pool and its initial member set in one atomic statement.
ALTER TABLE k8s_connector_pools
    ADD CONSTRAINT k8s_connector_pools_preferred_member_fk
        FOREIGN KEY (id, org_id, site_id, preferred_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT k8s_connector_pools_active_member_fk
        FOREIGN KEY (id, org_id, site_id, active_node_id)
        REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)
        DEFERRABLE INITIALLY DEFERRED;

-- A cluster is either on the old one-node contract or explicitly attached to
-- the new pool contract. This prevents a future reader from silently choosing
-- between two authorities during a mixed-version rollout.
ALTER TABLE k8s_clusters
    ADD COLUMN connector_pool_id uuid,
    ADD CONSTRAINT k8s_clusters_connector_pool_fk
        FOREIGN KEY (connector_pool_id, org_id, site_id, id)
        REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT k8s_clusters_connector_mode_check
        CHECK (connector_node_id IS NULL OR connector_pool_id IS NULL);

CREATE INDEX k8s_clusters_connector_pool_idx ON k8s_clusters (connector_pool_id)
    WHERE connector_pool_id IS NOT NULL;
