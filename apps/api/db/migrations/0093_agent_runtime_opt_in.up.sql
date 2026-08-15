-- F04: managed runtime synchronization is an explicit organization opt-in.
-- A paid licence unlocks the capability; it never enables it implicitly.
ALTER TABLE organizations
    ADD COLUMN managed_agent_runtime_enabled boolean NOT NULL DEFAULT false;
