-- SSI-8: how a site's LAN sees traffic that arrives from other sites.
--   preserve_source  the remote address is kept (the behaviour before this migration); the LAN needs a
--                    return route to the gateway.
--   gateway_address  the site's gateways source-NAT remote-site traffic to their own LAN address.
-- Every existing site keeps preserve_source: nothing about a running link changes on upgrade.
ALTER TABLE sites
    ADD COLUMN lan_egress text NOT NULL DEFAULT 'preserve_source'
    CONSTRAINT sites_lan_egress_check CHECK (lan_egress IN ('preserve_source', 'gateway_address'));
