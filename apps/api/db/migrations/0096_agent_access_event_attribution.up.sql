-- F07: preserve the attribution facts stamped by the applied gateway artifact.
-- Historical rows remain NULL: current policy/runtime state is not evidence of what
-- was applied when an older packet was observed.
ALTER TABLE access_events
    ADD COLUMN policy_hash text,
    ADD COLUMN policy_version integer,
    ADD COLUMN src_config_revision bigint,
    ADD COLUMN src_kind text,
    ADD COLUMN decision_reason text;

ALTER TABLE access_events
    ADD CONSTRAINT access_events_policy_hash_check
        CHECK (policy_hash IS NULL OR policy_hash ~ '^[0-9a-f]{12}$'),
    ADD CONSTRAINT access_events_policy_version_check
        CHECK (policy_version IS NULL OR policy_version >= 1),
    ADD CONSTRAINT access_events_src_config_revision_check
        CHECK (src_config_revision IS NULL OR src_config_revision >= 0),
    ADD CONSTRAINT access_events_src_kind_check
        CHECK (src_kind IS NULL OR src_kind IN ('human', 'agent')),
    ADD CONSTRAINT access_events_decision_reason_check
        CHECK (decision_reason IS NULL OR decision_reason IN (
            'matched_grant', 'no_matching_grant', 'grant_revoked', 'events_dropped'
        ));

CREATE INDEX access_events_org_agent_created_id_idx
    ON access_events (org_id, src_device_id, created_at DESC, id DESC)
    WHERE src_kind = 'agent';
