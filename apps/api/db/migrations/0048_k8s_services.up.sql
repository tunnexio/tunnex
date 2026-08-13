-- S10.3 Slice 1: expose in-cluster Kubernetes Services to the fabric via a per-Service VIP.
--
-- A k8s_cluster is fronted by ONE site's gateway (D1: one gateway = one site) and owns a disjoint
-- synthetic VIP RANGE (validated by subnetguard against the pool, every site subnet, and other clusters'
-- VIP ranges — the bidirectional disjointness law). A k8s_service is the STABLE IDENTITY of an exposed
-- Service; a grant references this id, and the compiler resolves id -> CURRENT vip at compile time (the
-- VIP-reassignment-safe shape — a destination with a stable id, NOT a source principal). The gateway
-- DNATs vip -> the real ClusterIP and rewrites DNS answers Service-name -> vip.

CREATE TABLE k8s_clusters (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id    uuid        NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    name       text        NOT NULL,
    -- The disjoint synthetic VIP range this cluster's exposed Services allocate /32s from. cidr type so
    -- Postgres stores it canonical (masked); subnetguard enforces disjointness at create time.
    vip_range  cidr        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name),
    -- A VIP range belongs to at most one cluster per org (a second cluster can't claim the same range).
    UNIQUE (org_id, vip_range)
);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_clusters
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX k8s_clusters_org_idx  ON k8s_clusters (org_id);
CREATE INDEX k8s_clusters_site_idx ON k8s_clusters (site_id);

CREATE TABLE k8s_services (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),  -- the STABLE Service identity a grant references
    org_id     uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    cluster_id uuid        NOT NULL REFERENCES k8s_clusters (id) ON DELETE CASCADE,
    name       text        NOT NULL,
    namespace  text        NOT NULL,
    protocol   text        NOT NULL DEFAULT 'any' CHECK (protocol IN ('any', 'tcp', 'udp')),
    port_low   int,
    port_high  int,
    -- The VIP allocated from the cluster's vip_range (ipalloc). A /32 host; inet stores the address.
    vip        inet        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    -- Soft-delete: a removed Service's row is retained so its id stays resolvable (a grant referencing it
    -- compiles to nothing, honestly) and its VIP is not immediately reassigned to a different Service.
    deleted_at timestamptz,
    -- A Service is unique by (cluster, namespace, name) among the LIVE rows; a VIP is unique per cluster
    -- among live rows. Partial unique indexes below enforce this without blocking re-expose after delete.
    CONSTRAINT k8s_services_port_range CHECK (
        (port_low IS NULL AND port_high IS NULL) OR
        (port_low IS NOT NULL AND port_high IS NOT NULL AND port_low <= port_high)
    )
);

CREATE UNIQUE INDEX k8s_services_ident_live ON k8s_services (cluster_id, namespace, name)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX k8s_services_vip_live ON k8s_services (cluster_id, vip)
    WHERE deleted_at IS NULL;
CREATE INDEX k8s_services_org_idx ON k8s_services (org_id) WHERE deleted_at IS NULL;

CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_services
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
