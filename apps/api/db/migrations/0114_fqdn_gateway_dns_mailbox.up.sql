-- S21 D9 / Option 1: durable agent-pull DNS RPC mailbox.
--
-- The existing gateway control channel is mTLS agent-pull, not a control-plane
-- outbound socket. Persisting each request makes it safe across API replicas,
-- leader changes and reconnects. The authenticated completion handler locks
-- this row before accepting an echoed response.
CREATE TABLE fqdn_gateway_dns_requests (
    request_id       uuid PRIMARY KEY,
    protocol_version smallint NOT NULL,
    org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    resource_id      uuid NOT NULL REFERENCES fqdn_resources(id) ON DELETE RESTRICT,
    site_id          uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    gateway_id       uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    hostname         text NOT NULL,
    record_types     jsonb NOT NULL,
    deadline         timestamptz NOT NULL,
    state            text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','completed','expired')),
    response         jsonb,
    created_at       timestamptz NOT NULL DEFAULT now(),
    completed_at     timestamptz,
    expired_at       timestamptz,
    CHECK ((state = 'completed') = (response IS NOT NULL))
);

CREATE INDEX fqdn_gateway_dns_requests_pending_gateway_idx
    ON fqdn_gateway_dns_requests(org_id, gateway_id, created_at)
    WHERE state = 'pending';

CREATE INDEX fqdn_gateway_dns_requests_pending_deadline_idx
    ON fqdn_gateway_dns_requests(deadline)
    WHERE state = 'pending';
