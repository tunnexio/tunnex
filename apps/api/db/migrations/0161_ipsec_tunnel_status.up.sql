-- Disposable nonsecret observation only; it grants no runtime authority.
CREATE TABLE ipsec_tunnel_status (
 connection_id uuid PRIMARY KEY,org_id uuid NOT NULL,node_id uuid NOT NULL,
 delivery_id uuid NOT NULL,desired_revision bigint NOT NULL CHECK(desired_revision>0),
 configuration_revision bigint NOT NULL CHECK(configuration_revision=1),
 certificate_serial text NOT NULL CHECK(length(certificate_serial)>0),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 tunnels jsonb NOT NULL CHECK(jsonb_typeof(tunnels)='array' AND jsonb_array_length(tunnels)=2 AND octet_length(tunnels::text)<2048),
 FOREIGN KEY(connection_id,org_id) REFERENCES ipsec_connections(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(delivery_id,connection_id,org_id) REFERENCES ipsec_runtime_deliveries(id,connection_id,org_id) ON DELETE RESTRICT
);
