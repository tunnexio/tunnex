CREATE TABLE sandbox_network_withdrawals (
 sandbox_id uuid PRIMARY KEY REFERENCES sandboxes(id) ON DELETE CASCADE,
 org_id uuid NOT NULL REFERENCES organizations(id),
 generation bigint NOT NULL CHECK(generation>0),
 operation_id uuid NOT NULL REFERENCES sandbox_launch_operations(id),
 network_generation bigint NOT NULL CHECK(network_generation>0),
 peer_id uuid NOT NULL REFERENCES devices(id),
 runtime_id text NOT NULL CHECK(runtime_id ~ '^[a-f0-9]{64}$'),
 spec_hash text NOT NULL CHECK(spec_hash ~ '^[a-f0-9]{64}$'),
 observed_at timestamptz NOT NULL DEFAULT now()
);
