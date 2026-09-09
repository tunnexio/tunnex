CREATE TABLE ai_gateway_team_policies (
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 team_id uuid NOT NULL,
 models text[] NOT NULL CHECK (cardinality(models) BETWEEN 1 AND 32),
 key_ids text[] NOT NULL CHECK (cardinality(key_ids) BETWEEN 1 AND 8),
 daily_cost_limit double precision CHECK (daily_cost_limit > 0 AND daily_cost_limit <= 100000),
 revision bigint NOT NULL CHECK (revision > 0),
 PRIMARY KEY(org_id,team_id),
 FOREIGN KEY(team_id,org_id) REFERENCES agent_groups(id,org_id) ON DELETE RESTRICT
);
CREATE TABLE ai_gateway_assignments (
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 device_id uuid NOT NULL,
 team_id uuid NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 models_override text[] NOT NULL DEFAULT '{}' CHECK (cardinality(models_override) <= 32),
 revision bigint NOT NULL CHECK (revision > 0),
 applied_revision bigint NOT NULL DEFAULT 0 CHECK (applied_revision >= 0 AND applied_revision <= revision),
 applied_team_revision bigint NOT NULL DEFAULT 0 CHECK (applied_team_revision >= 0),
 status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','error','disabled')),
 last_reconcile_at timestamptz,
 PRIMARY KEY(org_id,device_id),
 FOREIGN KEY(device_id,org_id) REFERENCES devices(id,org_id) ON DELETE CASCADE,
 FOREIGN KEY(org_id,team_id) REFERENCES ai_gateway_team_policies(org_id,team_id) ON DELETE RESTRICT
);
CREATE TABLE ai_gateway_key_bindings (
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 device_id uuid NOT NULL,
 team_id uuid NOT NULL,
 native_key_id text NOT NULL UNIQUE CHECK (char_length(native_key_id) BETWEEN 1 AND 255),
 sealed_key text NOT NULL CHECK (octet_length(sealed_key) BETWEEN 1 AND 8192),
 binding_revision bigint NOT NULL CHECK (binding_revision > 0),
 created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 PRIMARY KEY(org_id,device_id,team_id),
 FOREIGN KEY(device_id,org_id) REFERENCES devices(id,org_id) ON DELETE CASCADE,
 FOREIGN KEY(org_id,team_id) REFERENCES ai_gateway_team_policies(org_id,team_id) ON DELETE RESTRICT
);
COMMENT ON TABLE ai_gateway_key_bindings IS 'Stable native accounting identities; retained across team moves, not a second usage ledger.';

CREATE TRIGGER set_updated_at BEFORE UPDATE ON ai_gateway_key_bindings FOR EACH ROW EXECUTE FUNCTION set_updated_at();
