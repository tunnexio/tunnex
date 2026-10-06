-- Public job material and sealed initiating-session binding; never gateway private keys.
CREATE TABLE server_access_enrollments (
 id uuid PRIMARY KEY,
 org_id uuid NOT NULL,
 server_id uuid NOT NULL,
 gateway_id uuid NOT NULL,
 state text NOT NULL CHECK(state IN ('preparing','awaiting_authorization','queued','running','succeeded','failed','cancelled','expired')),
 expires_at timestamptz NOT NULL,
 payload jsonb NOT NULL,
 FOREIGN KEY (org_id,server_id) REFERENCES server_access_servers(org_id,id)
);
CREATE UNIQUE INDEX server_access_enrollment_active ON server_access_enrollments(org_id,server_id)
 WHERE state IN ('preparing','awaiting_authorization','queued','running');
CREATE INDEX server_access_enrollment_gateway ON server_access_enrollments(org_id,gateway_id,expires_at);

ALTER TABLE server_access_servers DROP CONSTRAINT server_access_servers_accounts_check;
ALTER TABLE server_access_servers ADD CONSTRAINT server_access_servers_accounts_check CHECK(cardinality(accounts) BETWEEN 0 AND 16);
