-- Reversible F02 quota rollback. Device identities and their history remain.
ALTER TABLE organizations
    DROP COLUMN IF EXISTS max_agent_identities;
