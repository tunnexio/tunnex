-- Additive, default-off NAT signaling. One bounded current mailbox per device.
CREATE TABLE connectivity_profiles (
    org_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON connectivity_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE connectivity_sessions (
    device_id uuid PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    gateway_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    session_id uuid NOT NULL UNIQUE,
    generation bigint NOT NULL CHECK (generation > 0),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked boolean NOT NULL DEFAULT false,
    device_sequence bigint NOT NULL DEFAULT 0 CHECK (device_sequence BETWEEN 0 AND 64),
    gateway_sequence bigint NOT NULL DEFAULT 0 CHECK (gateway_sequence BETWEEN 0 AND 64),
    -- Preserve original UTF-8 bytes: jsonb normalization can expand an otherwise
    -- valid size-bounded snapshot. This mailbox does not query JSON fields.
    device_payload json NOT NULL DEFAULT '{}'::json,
    gateway_payload json NOT NULL DEFAULT '{}'::json,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
    CHECK (json_typeof(device_payload) = 'object' AND octet_length(device_payload::text) <= 16384),
    CHECK (json_typeof(gateway_payload) = 'object' AND octet_length(gateway_payload::text) <= 16384)
);
CREATE INDEX connectivity_sessions_org_gateway_idx ON connectivity_sessions(org_id, gateway_id);
