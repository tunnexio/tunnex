-- Separate sandbox bootstrap/runtime identities; existing agent tables unchanged.
CREATE TABLE sandbox_bootstrap_tokens (
 id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
 org_id uuid NOT NULL,
 sandbox_id uuid NOT NULL,
 gateway_node_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+interval '1 hour'),
 consumed_at timestamptz,
 FOREIGN KEY(org_id,sandbox_id) REFERENCES sandboxes(org_id,id),
 FOREIGN KEY(org_id,gateway_node_id) REFERENCES nodes(org_id,id)
);
CREATE UNIQUE INDEX sandbox_bootstrap_pending_key ON sandbox_bootstrap_tokens(sandbox_id,generation) WHERE consumed_at IS NULL;
CREATE TABLE sandbox_runtime_credentials (
 org_id uuid NOT NULL,
 sandbox_id uuid PRIMARY KEY,
 peer_id uuid NOT NULL UNIQUE,
 token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
 created_at timestamptz NOT NULL DEFAULT now(),
 revoked_at timestamptz,
 FOREIGN KEY(org_id,sandbox_id) REFERENCES sandboxes(org_id,id),
 FOREIGN KEY(org_id,peer_id) REFERENCES devices(org_id,id)
);
CREATE FUNCTION sandbox_runtime_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM sandboxes s JOIN devices d ON d.id=s.peer_id
  WHERE s.id=NEW.sandbox_id AND s.org_id=NEW.org_id AND s.peer_id=NEW.peer_id AND d.kind='sandbox' AND d.org_id=s.org_id AND d.user_id=s.creator_id) THEN
  RAISE EXCEPTION 'sandbox runtime credential requires matching bound sandbox peer';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sandbox_runtime_binding BEFORE INSERT OR UPDATE ON sandbox_runtime_credentials FOR EACH ROW EXECUTE FUNCTION sandbox_runtime_binding();
