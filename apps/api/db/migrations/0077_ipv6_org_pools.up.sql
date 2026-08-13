-- S15: deployment IPv6 pool allocation without changing existing sqlc SELECT * contracts.
-- One persisted /64 per organization prevents a restart from deriving a different prefix.
CREATE TABLE org_ipv6_pools (
    org_id    uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    pool_cidr text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (pool_cidr LIKE '%:%/%')
);

CREATE UNIQUE INDEX org_ipv6_pools_cidr_key ON org_ipv6_pools (pool_cidr);
