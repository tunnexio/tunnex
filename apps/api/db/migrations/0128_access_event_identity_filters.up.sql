-- Access-event identity filters use the immutable attribution captured on the
-- event row. Replace the agent-only access path with a device-wide one and add
-- the equivalent user path. Both indexes lead with org_id because every query
-- is tenant-scoped, then carry the complete keyset order.
-- Operational choice: build these as plain transactional indexes so the swap
-- is atomic and reversible. This can briefly block event writes in proportion
-- to the whole multi-tenant table; the per-org asynchronous cap is not a bound
-- on total table size, so schedule this migration in a controlled window.

DROP INDEX access_events_org_agent_created_id_idx;

CREATE INDEX access_events_org_device_created_id_idx
    ON access_events (org_id, src_device_id, created_at DESC, id DESC)
    WHERE src_device_id IS NOT NULL;

CREATE INDEX access_events_org_user_created_id_idx
    ON access_events (org_id, src_user_id, created_at DESC, id DESC)
    WHERE src_user_id IS NOT NULL;
