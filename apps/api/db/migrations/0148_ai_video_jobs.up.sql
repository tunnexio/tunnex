CREATE TABLE ai_video_jobs (
 id uuid PRIMARY KEY,
 org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 device_id uuid NOT NULL,
 model text NOT NULL CHECK (char_length(model) BETWEEN 1 AND 255),
 idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 16 AND 128),
 request_hash bytea NOT NULL CHECK (octet_length(request_hash)=32),
 provider_id text NOT NULL DEFAULT '' CHECK (char_length(provider_id)<=1024),
 state text NOT NULL CHECK (state IN ('uncertain','queued','in_progress','completed','failed')),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now()+interval '24 hours',
 FOREIGN KEY(device_id,org_id) REFERENCES devices(id,org_id) ON DELETE CASCADE,
 UNIQUE(org_id,device_id,idempotency_key)
);
CREATE INDEX ai_video_jobs_expiry_idx ON ai_video_jobs(expires_at);
CREATE INDEX ai_video_jobs_owner_state_idx ON ai_video_jobs(org_id,device_id,state);
COMMENT ON TABLE ai_video_jobs IS 'Opaque tenant-owned video handles; no prompts, credentials, generated content or provider error bodies. Uncertain submissions are never retried automatically.';
