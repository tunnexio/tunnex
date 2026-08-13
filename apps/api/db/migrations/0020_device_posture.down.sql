-- Reverse S7.3 device posture. Any pending devices must first leave the `pending`
-- state (it will not exist after the down) — treat them as revoked (fail-closed: an
-- unapproved device does not silently become active), so restoring the old CHECK can't
-- fail on a leftover pending row.
UPDATE devices SET status = 'revoked', revoked_at = now(), assigned_ip = NULL
WHERE status = 'pending';

-- Restore the active-only address-uniqueness index (pending rows are gone above).
DROP INDEX IF EXISTS devices_org_ip_key;
CREATE UNIQUE INDEX devices_org_ip_key ON devices (org_id, assigned_ip)
    WHERE assigned_ip IS NOT NULL AND status = 'active' AND deleted_at IS NULL;

ALTER TABLE organizations DROP COLUMN IF EXISTS device_approval;
ALTER TABLE devices DROP COLUMN IF EXISTS approved_by;

ALTER TABLE devices DROP CONSTRAINT devices_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_status_check
    CHECK (status IN ('active', 'revoked'));
