-- S7.3 device posture (basic): an org-level device-approval gate.
--
-- A device may now be `pending` (enrolled, awaiting admin approval) in addition to
-- `active` / `revoked`. `pending` is a real lifecycle state: a pending device holds its
-- assigned pool IP from creation but is EXCLUDED from every `status='active'` reader
-- (peer desired-state, compiler input, per-user cap, pubkey uniqueness) — so it gets no
-- tunnel and no grants until approved. The ONE reader that must still see it is the IP
-- ALLOCATOR (its held IP is in-flight, not free) — handled in queries, not schema.

-- Extend the status domain. (The inline column CHECK is named devices_status_check.)
ALTER TABLE devices DROP CONSTRAINT devices_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_status_check
    CHECK (status IN ('active', 'revoked', 'pending'));

-- approved_by: who explicitly approved this device. NULL = grandfathered (active before
-- the org turned approval on) OR auto-active (approval off) — i.e. NOT human-approved.
-- Set = approved by that actor. Lets S7.4 render grandfathered ≠ approved; the data
-- exists now (D4). SET NULL on approver deletion — attribution is best-effort (the audit
-- log holds the durable record); a device must not break because its approver left.
ALTER TABLE devices ADD COLUMN approved_by uuid REFERENCES users (id) ON DELETE SET NULL;

-- Org-level gate, default OFF (no break for existing orgs / the open build). Mirrors
-- zero_trust_mode: enterprise-gated, a desired-state/compiler INPUT, not a special-case.
ALTER TABLE organizations ADD COLUMN device_approval text NOT NULL DEFAULT 'off'
    CHECK (device_approval IN ('off', 'on'));

-- A pending device HOLDS its assigned pool IP from creation, so the org-wide address
-- uniqueness backstop must cover it too — the old index was partial on status='active'
-- ONLY, which would let a new ACTIVE device silently take a pending device's IP (the
-- partial index can't see the pending row), producing a duplicate that only surfaces
-- (as a hard failure) when the pending device is approved. Widen to active+pending so
-- the DB backstops what the allocator (ListActiveDeviceAllocations, also widened) already
-- prevents. Revoked/rejected devices have assigned_ip=NULL, so they never contend.
DROP INDEX IF EXISTS devices_org_ip_key;
CREATE UNIQUE INDEX devices_org_ip_key ON devices (org_id, assigned_ip)
    WHERE assigned_ip IS NOT NULL AND status IN ('active', 'pending') AND deleted_at IS NULL;
