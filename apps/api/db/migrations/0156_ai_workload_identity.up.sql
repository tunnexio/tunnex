-- Workload authority is independent of human/device lifecycle. Retained native
-- bindings account for all replicas without granting any network authority.
CREATE TABLE ai_workloads (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    enabled boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    credential_epoch bigint NOT NULL DEFAULT 1 CHECK (credential_epoch > 0),
    daily_usd_threshold double precision CHECK (daily_usd_threshold > 0 AND daily_usd_threshold <= 100000),
    applied_revision bigint NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','revoked','error')),
    native_key_id text NOT NULL DEFAULT '',
    sealed_key text NOT NULL DEFAULT '',
    binding_revision bigint NOT NULL DEFAULT 0,
    last_reconcile_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(org_id,id),
    UNIQUE(org_id,name)
);
CREATE TABLE ai_workload_models (
    org_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    connection_id uuid NOT NULL REFERENCES ai_provider_connections(id),
    model text NOT NULL CHECK (char_length(model) BETWEEN 1 AND 255),
    mode text NOT NULL,
    PRIMARY KEY(workload_id,model),
    FOREIGN KEY(org_id,workload_id) REFERENCES ai_workloads(org_id,id) ON DELETE CASCADE
);
CREATE INDEX ai_workload_model_connection ON ai_workload_models(org_id,connection_id);
CREATE TABLE ai_workload_enrollment_keys (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    secret_hash bytea NOT NULL UNIQUE CHECK (octet_length(secret_hash)=32),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    reusable boolean NOT NULL,
    ephemeral boolean NOT NULL DEFAULT true,
    max_uses bigint NOT NULL DEFAULT 0 CHECK (max_uses >= 0),
    uses bigint NOT NULL DEFAULT 0 CHECK (uses >= 0),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(org_id,workload_id,id),
    FOREIGN KEY(org_id,workload_id) REFERENCES ai_workloads(org_id,id) ON DELETE CASCADE,
    CHECK (reusable OR max_uses=1),
    CHECK (max_uses=0 OR uses<=max_uses)
);
CREATE TABLE ai_workload_instances (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    enrollment_key_id uuid NOT NULL,
    enrollment_request_id uuid NOT NULL,
    public_key bytea NOT NULL CHECK (octet_length(public_key)=32),
    key_generation bigint NOT NULL DEFAULT 1 CHECK (key_generation > 0),
    previous_public_key bytea,
    rotation_id uuid,
    ephemeral boolean NOT NULL,
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','revoked','retired')),
    last_contact_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(org_id,workload_id,id),
    UNIQUE(enrollment_key_id,enrollment_request_id),
    FOREIGN KEY(org_id,workload_id,enrollment_key_id) REFERENCES ai_workload_enrollment_keys(org_id,workload_id,id)
);
CREATE INDEX ai_workload_instances_contact ON ai_workload_instances(last_contact_at) WHERE ephemeral AND state='active';
CREATE TABLE ai_workload_assertions (
    instance_id uuid NOT NULL REFERENCES ai_workload_instances(id) ON DELETE CASCADE,
    jti text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(instance_id,jti)
);
CREATE INDEX ai_workload_assertions_expiry ON ai_workload_assertions(expires_at);
CREATE TABLE ai_workload_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash)=32),
    org_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    audience text NOT NULL CHECK (audience='tunnex-ai'),
    key_generation bigint NOT NULL,
    workload_epoch bigint NOT NULL,
    org_revision bigint NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY(org_id,workload_id,instance_id) REFERENCES ai_workload_instances(org_id,workload_id,id) ON DELETE CASCADE
);
CREATE INDEX ai_workload_tokens_instance ON ai_workload_tokens(instance_id,created_at);
CREATE INDEX ai_workload_tokens_expiry ON ai_workload_tokens(expires_at);

ALTER TABLE ai_video_jobs ADD COLUMN workload_id uuid REFERENCES ai_workloads(id);
ALTER TABLE ai_video_jobs DROP CONSTRAINT ai_video_owner;
ALTER TABLE ai_video_jobs ADD CONSTRAINT ai_video_owner CHECK (num_nonnulls(device_id,user_id,workload_id)=1);
CREATE UNIQUE INDEX ai_video_workload_idempotency ON ai_video_jobs(org_id,workload_id,idempotency_key) WHERE workload_id IS NOT NULL;
