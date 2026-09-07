-- AI-1 is Community core, independently opt-in and default off.
ALTER TABLE organizations ADD COLUMN ai_gateway_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE organizations ADD COLUMN ai_gateway_revision bigint NOT NULL DEFAULT 1 CHECK (ai_gateway_revision > 0);
CREATE TABLE ai_gateway_credentials (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id uuid NOT NULL,
    runtime_revision bigint NOT NULL CHECK (runtime_revision > 0),
    audience text NOT NULL CHECK (audience = 'tunnex-ai'),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    FOREIGN KEY (org_id, device_id) REFERENCES devices(org_id,id) ON DELETE CASCADE,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes')
);
CREATE INDEX ai_gateway_credentials_device ON ai_gateway_credentials(org_id,device_id,expires_at);
