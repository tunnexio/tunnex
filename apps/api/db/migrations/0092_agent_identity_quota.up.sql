-- F02: explicit nullable organization-wide managed-agent identity quota.
-- NULL means unlimited; the device-create transaction enforces this under the
-- existing organization advisory lock.
ALTER TABLE organizations
    ADD COLUMN max_agent_identities integer
    CHECK (max_agent_identities IS NULL OR max_agent_identities >= 0);
