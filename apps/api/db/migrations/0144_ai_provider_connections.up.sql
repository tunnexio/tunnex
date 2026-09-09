DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM ai_gateway_team_policies, unnest(key_ids) AS k WHERE k LIKE 'tnx-managed-%') THEN
  RAISE EXCEPTION 'AI provider migration: reserved tnx-managed- key reference exists; rename operator key and update team references before retry';
 END IF;
END $$;
CREATE TABLE ai_provider_legacy_keys (
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 key_id text COLLATE "C" NOT NULL CHECK (key_id NOT LIKE 'tnx-managed-%'),
 PRIMARY KEY(org_id,key_id)
);
INSERT INTO ai_provider_legacy_keys SELECT DISTINCT org_id,unnest(key_ids) FROM ai_gateway_team_policies;
CREATE TABLE ai_provider_connections (
 id uuid PRIMARY KEY,
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 key_id text COLLATE "C" NOT NULL UNIQUE CHECK (key_id = 'tnx-managed-' || id::text),
 provider text NOT NULL CHECK(provider='openrouter'),
 name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 80),
 models text[] NOT NULL CHECK(cardinality(models) BETWEEN 1 AND 32),
 enabled boolean NOT NULL DEFAULT false,
 revision bigint NOT NULL CHECK(revision>0),
 applied_revision bigint NOT NULL DEFAULT 0 CHECK(applied_revision BETWEEN 0 AND revision),
 status text NOT NULL CHECK(status IN ('pending','applied','error','disabled')),
 last_test_status text NOT NULL DEFAULT 'untested' CHECK(last_test_status IN ('untested','success','failed')),
 last_test_at timestamptz,
 deleted_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
CREATE INDEX ai_provider_connections_org ON ai_provider_connections(org_id,id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON ai_provider_connections FOR EACH ROW EXECUTE FUNCTION set_updated_at();
COMMENT ON TABLE ai_provider_connections IS 'Ownership and desired state only. Provider secrets live exclusively in private engine storage. Tombstones reserve ownership.';
