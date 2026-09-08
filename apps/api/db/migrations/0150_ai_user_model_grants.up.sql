CREATE TABLE ai_user_model_grants (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id uuid REFERENCES user_groups(id) ON DELETE SET NULL,
    group_ref uuid NOT NULL,
    group_name text NOT NULL,
    connection_id uuid NOT NULL REFERENCES ai_provider_connections(id),
    model text NOT NULL CHECK (char_length(model) BETWEEN 1 AND 255),
    mode text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    applied_revision bigint NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','revoked','error')),
    native_key_id text NOT NULL DEFAULT '',
    sealed_key text NOT NULL DEFAULT '',
    binding_revision bigint NOT NULL DEFAULT 0,
    last_reconcile_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(org_id,group_id,connection_id,model)
);
CREATE INDEX ai_user_model_grants_org_model_idx ON ai_user_model_grants(org_id,model);
COMMENT ON TABLE ai_user_model_grants IS 'Human group model grants; deleted groups lose access immediately. Retained rows preserve native usage attribution. No provider secrets.';

ALTER TABLE ai_video_jobs ALTER COLUMN device_id DROP NOT NULL;
ALTER TABLE ai_video_jobs ADD COLUMN user_id uuid REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE ai_video_jobs ADD CONSTRAINT ai_video_owner CHECK ((device_id IS NULL) <> (user_id IS NULL));
CREATE UNIQUE INDEX ai_video_user_idempotency ON ai_video_jobs(org_id,user_id,idempotency_key) WHERE user_id IS NOT NULL;
