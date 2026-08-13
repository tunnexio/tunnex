-- S8.1 site/gateway model (EPIC 8 opener, D6). A SITE is a first-class org ENTITY that OWNS a
-- gateway node — NOT a role/attribute of the node. The argued consequence (docs/S8.1-decisions.md
-- D6): replacing a failed gateway box must NOT destroy the site's identity, subnets, or future
-- advertisements — all of which are site-scoped, not node-scoped. So the node BINDS to the site
-- (nodes.site_id), and replacing it is a re-bind; the site survives.
--
-- v1 enforces SINGLE-NODE-per-site (the partial unique index below). The multi-node/HA seam is
-- reserved — relaxing that index is the whole change, no table reshape (D6 HA seam).
--
-- RESERVED seams carried NOW to avoid a later migration (created, UNPOPULATED, unread until their
-- story): link_transport (D4 IPsec seam), link_mtu (D9a MSS-clamp seam, S8.2), dns_forwarding
-- (S8.4). v1 single-node: a site has one gateway = one uplink, so transport/mtu live on the SITE;
-- they promote to a per-link table when the HA/multi-link seam unparks.

CREATE TABLE sites (
    id             uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id         uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name           text NOT NULL,
    -- RESERVED (D4): the site uplink transport. wireguard is the ONLY implemented value; the enum
    -- reserves the parked IPsec-interop seam without a later migration. Routing + Zero-Trust
    -- enforcement are transport-agnostic (they never branch on this).
    link_transport text NOT NULL DEFAULT 'wireguard' CHECK (link_transport IN ('wireguard')),
    -- RESERVED (D9a): per-link MTU for the S8.2 double-encapsulation MSS-clamp decision. NULL = default.
    link_mtu       int CHECK (link_mtu IS NULL OR link_mtu BETWEEN 576 AND 9000),
    -- RESERVED (S8.4): cross-site DNS forwarding entries (domain -> that site's internal resolver).
    -- Empty until S8.4 compiles them; a JSONB array keeps the shape open without a migration.
    dns_forwarding jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE INDEX sites_org_id_idx ON sites (org_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON sites
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- site_subnets: the LAN subnets a site routes. Advertisement/approval + pool-disjointness are S8.1
-- Slice 4; this is the model only. cidr is the routed network (host bits masked by the cidr type).
CREATE TABLE site_subnets (
    id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    site_id    uuid NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    cidr       cidr NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (site_id, cidr)
);
CREATE INDEX site_subnets_site_id_idx ON site_subnets (site_id);

-- nodes.site_id BINDS a gateway node to the site it serves. NULLABLE and NULL BY DEFAULT: every
-- existing gateway is site-LESS (a plain tunnex-node agent, not a site router) and MUST stay valid
-- — a NULL here is the norm, never an error. ON DELETE SET NULL: deleting a site un-binds its node
-- (the node row survives; the SITE entity is what goes). v1 SINGLE-NODE-per-site: the partial
-- unique index enforces at most one node per site (the HA/multi-node seam relaxes it later).
ALTER TABLE nodes ADD COLUMN site_id uuid REFERENCES sites (id) ON DELETE SET NULL;
CREATE UNIQUE INDEX nodes_site_id_uniq ON nodes (site_id) WHERE site_id IS NOT NULL;
