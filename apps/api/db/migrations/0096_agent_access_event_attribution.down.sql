-- Preservation-first rollback: once F07-attributed events exist, dropping these
-- columns would erase event-time facts. Refuse before changing schema or data.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM access_events
        WHERE policy_hash IS NOT NULL
           OR policy_version IS NOT NULL
           OR src_config_revision IS NOT NULL
           OR src_kind IS NOT NULL
           OR decision_reason IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'cannot roll back 0096: attributed access events exist';
    END IF;
END $$;

DROP INDEX access_events_org_agent_created_id_idx;

ALTER TABLE access_events
    DROP CONSTRAINT access_events_decision_reason_check,
    DROP CONSTRAINT access_events_src_kind_check,
    DROP CONSTRAINT access_events_src_config_revision_check,
    DROP CONSTRAINT access_events_policy_version_check,
    DROP CONSTRAINT access_events_policy_hash_check,
    DROP COLUMN decision_reason,
    DROP COLUMN src_kind,
    DROP COLUMN src_config_revision,
    DROP COLUMN policy_version,
    DROP COLUMN policy_hash;
