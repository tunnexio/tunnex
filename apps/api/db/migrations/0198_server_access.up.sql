CREATE UNIQUE INDEX server_access_nodes_tenant_identity ON nodes(org_id,id);
CREATE UNIQUE INDEX server_access_groups_tenant_identity ON user_groups(org_id,id);
-- Browser SSH authority is separate from VPN and web-application grants.
CREATE TABLE server_access_settings (
 org_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
 enabled boolean NOT NULL DEFAULT false,
 ca_private_sealed bytea NOT NULL,
 ca_public text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE server_access_servers (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 gateway_id uuid NOT NULL,
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
 private_ip inet NOT NULL,
 ssh_port integer NOT NULL CHECK(ssh_port BETWEEN 1 AND 65535),
 host_fingerprint text NOT NULL,
 accounts text[] NOT NULL CHECK(cardinality(accounts) BETWEEN 1 AND 16),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 enabled boolean NOT NULL DEFAULT false,
 recording_enabled boolean NOT NULL DEFAULT false,
 idle_timeout_seconds integer NOT NULL DEFAULT 900 CHECK(idle_timeout_seconds BETWEEN 60 AND 900),
 max_session_seconds integer NOT NULL DEFAULT 3600 CHECK(max_session_seconds BETWEEN 60 AND 3600),
 ready_accounts text[] NOT NULL DEFAULT '{}',
 last_error text NOT NULL DEFAULT '',
 checked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(org_id,id),
 FOREIGN KEY(org_id,gateway_id) REFERENCES nodes(org_id,id) ON DELETE CASCADE
);
CREATE TABLE server_access_grants (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL,
 server_id uuid NOT NULL,
 account text NOT NULL,
 user_id uuid,
 group_id uuid,
 starts_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 enabled boolean NOT NULL DEFAULT true,
 created_by uuid NOT NULL REFERENCES users(id),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(org_id,id),
 FOREIGN KEY(org_id,server_id) REFERENCES server_access_servers(org_id,id) ON DELETE CASCADE,
 FOREIGN KEY(org_id,user_id) REFERENCES memberships(org_id,user_id) ON DELETE CASCADE,
 FOREIGN KEY(org_id,group_id) REFERENCES user_groups(org_id,id) ON DELETE CASCADE,
 CHECK((user_id IS NULL) <> (group_id IS NULL)),
 CHECK(expires_at>starts_at AND expires_at<=starts_at+interval '7 days')
);
CREATE INDEX server_access_grants_current ON server_access_grants(org_id,server_id,account) WHERE enabled;
CREATE TABLE server_access_sessions (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL,
 server_id uuid NOT NULL,
 gateway_id uuid NOT NULL,
 user_id uuid NOT NULL REFERENCES users(id),
 parent_sealed bytea NOT NULL,
 parent_hash bytea NOT NULL,
 parent_epoch bigint NOT NULL,
 grant_id uuid,
 account text NOT NULL,
 revision bigint NOT NULL,
 gateway_serial text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('terminal','check')),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','connecting','connected','passed','failed','ended')),
 reason text NOT NULL DEFAULT '',
 expires_at timestamptz NOT NULL,
 idle_deadline timestamptz NOT NULL,
 browser_claimed_at timestamptz,
 public_key_hash bytea,
 recording_enabled boolean NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 ended_at timestamptz,
 UNIQUE(org_id,id),
 FOREIGN KEY(org_id,server_id) REFERENCES server_access_servers(org_id,id) ON DELETE CASCADE,
 FOREIGN KEY(org_id,gateway_id) REFERENCES nodes(org_id,id) ON DELETE CASCADE,
 FOREIGN KEY(org_id,grant_id) REFERENCES server_access_grants(org_id,id) ON DELETE CASCADE
);
CREATE INDEX server_access_sessions_gateway ON server_access_sessions(org_id,gateway_id,status);
CREATE INDEX server_access_sessions_actor ON server_access_sessions(org_id,user_id,created_at DESC);

CREATE TABLE server_access_gateway_runtime (
 org_id uuid NOT NULL,
 gateway_id uuid NOT NULL,
 cert_serial text NOT NULL,
 protocol_version integer NOT NULL CHECK(protocol_version=1),
 observed_at timestamptz NOT NULL,
 PRIMARY KEY(org_id,gateway_id),
 FOREIGN KEY(org_id,gateway_id) REFERENCES nodes(org_id,id) ON DELETE CASCADE
);
