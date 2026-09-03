DROP INDEX access_events_org_user_created_id_idx;
DROP INDEX access_events_org_device_created_id_idx;

CREATE INDEX access_events_org_agent_created_id_idx
    ON access_events (org_id, src_device_id, created_at DESC, id DESC)
    WHERE src_kind = 'agent';
