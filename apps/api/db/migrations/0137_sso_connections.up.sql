CREATE TABLE sso_connections (
 id uuid PRIMARY KEY,
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 name text NOT NULL,
 provider text NOT NULL CHECK (provider IN ('okta','oidc')),
 issuer_url text NOT NULL,
 client_id text NOT NULL,
 client_secret_sealed bytea NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 revision bigint NOT NULL DEFAULT 1,
 tested_revision bigint,
 tested_at timestamptz,
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE (org_id,id)
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON sso_connections FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TABLE sso_connection_identities (
 connection_id uuid NOT NULL REFERENCES sso_connections(id) ON DELETE CASCADE,
 issuer_url text NOT NULL,
 subject text NOT NULL,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 PRIMARY KEY (connection_id,issuer_url,subject),
 UNIQUE (connection_id,user_id)
);
