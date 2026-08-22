-- F19: route projection is managed desired state. Remember the last
-- canonical allowed-IP set so a policy edit creates a new runtime revision.
ALTER TABLE agent_runtime_state
    ADD COLUMN route_fingerprint text NOT NULL DEFAULT ''
    CHECK (char_length(route_fingerprint) <= 64);
