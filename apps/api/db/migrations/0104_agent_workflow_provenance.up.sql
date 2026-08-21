-- F15 follows F14's 0103 MCP policy migration. Workflow provenance is an
-- append-only assertion ledger, deliberately separate from F07 flow events.
CREATE TABLE agent_workflow_signing_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    UNIQUE (device_id, key_id)
);

CREATE INDEX agent_workflow_signing_keys_lookup_idx
    ON agent_workflow_signing_keys (org_id, device_id, key_id)
    WHERE state = 'active';

CREATE TABLE agent_workflow_provenance_used_assertions (
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    assertion_id uuid NOT NULL,
    claimed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, assertion_id)
);

CREATE TABLE agent_workflow_provenance (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    assertion_id uuid NOT NULL,
    key_id text NOT NULL,
    workflow_id text,
    run_id text,
    trigger_kind text,
    initiating_subject_ref text,
    tool text,
    resource text,
    issued_at timestamptz,
    expires_at timestamptz,
    signature text,
    verification_state text NOT NULL CHECK (verification_state IN ('verified', 'unverified')),
    verification_reason text NOT NULL CHECK (verification_reason IN ('verified', 'malformed', 'expired', 'not_yet_valid', 'lifetime_exceeded', 'unknown_key', 'revoked_key', 'bad_signature', 'replay')),
    received_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((verification_state = 'verified') = (verification_reason = 'verified'))
);

CREATE INDEX agent_workflow_provenance_agent_received_idx
    ON agent_workflow_provenance (org_id, device_id, received_at DESC, id DESC);

CREATE FUNCTION agent_workflow_provenance_prevent_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'agent workflow provenance is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION agent_workflow_provenance_prevent_direct_delete() RETURNS trigger AS $$
BEGIN
    -- Preserve normal ON DELETE CASCADE lifecycle cleanup while rejecting a
    -- direct attempt to erase evidence from a still-present agent.
    IF EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = OLD.device_id AND d.org_id = OLD.org_id
    ) THEN
        RAISE EXCEPTION 'agent workflow provenance is append-only';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER agent_workflow_provenance_no_update
    BEFORE UPDATE ON agent_workflow_provenance
    FOR EACH ROW EXECUTE FUNCTION agent_workflow_provenance_prevent_update();

CREATE TRIGGER agent_workflow_provenance_no_delete
    BEFORE DELETE ON agent_workflow_provenance
    FOR EACH ROW EXECUTE FUNCTION agent_workflow_provenance_prevent_direct_delete();

COMMENT ON TABLE agent_workflow_provenance IS
    'F15 append-only signed workflow assertions. Unverified entries are evidence only and never imply a workflow or human trigger.';
