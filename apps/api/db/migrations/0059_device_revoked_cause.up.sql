-- S13.1 D5 (Wall 6): record WHY a device was revoked, and stop destroying WHAT the revocation took.
--
-- WALL 6, from the epic's verify pass: recovering a gateway did not recover its USERS. Revoking a gateway cascades
-- to every device homed on it, so the documented recovery procedure — followed correctly and to completion — handed
-- back a working gateway with ZERO users, each needing a re-issued one-time config. One rebuild became a fleet-wide
-- user event, invisible until people called.
--
-- Restoring them safely needs one fact the schema did not have: WHY each device was revoked.
--
--   'cascade'    — revoked because its gateway was. RESTORABLE: nobody decided this device should stop.
--   'deliberate' — an operator revoked this device (a lost laptop). NEVER restorable by a gateway coming back.
--
-- Those two render identically today, which is why restore could not be built at all: un-revoking the cascade set
-- would have resurrected deliberately-revoked devices, and refusing to un-revoke anything leaves Wall 6 standing.
-- The column IS the mechanism.
--
-- AND THE ADDRESS STOPS BEING DESTROYED. Both revoke paths set assigned_ip = NULL, so a cascade-revoked device had
-- lost the record of the address it held — making the original unreclaimable IN PRINCIPLE, not merely in
-- contention. That is the same defect as the site_id unbind reverted earlier in this epic, one column over:
-- REVOCATION PRESERVES WHAT IT INVALIDATES.
--
-- Keeping it is free, because the two readers that define "this address is taken" both filter on status:
--   devices_org_ip_key   UNIQUE (org_id, assigned_ip) WHERE ... status IN ('active','pending') ...
--   ListActiveDeviceAllocations  ... WHERE ... status IN ('active','pending') ...
-- so a revoked row holding an address neither blocks reallocation nor reads as a live allocation. The pool is
-- unaffected; the record survives; and restore can ASK the oracle whether the address was taken meanwhile.
--
-- NULL cause = revoked before this column existed. Honestly unknown, and therefore NOT restorable: reviving a
-- device whose reason nobody recorded is exactly the deliberate-revocation risk this column exists to avoid.
ALTER TABLE devices ADD COLUMN revoked_cause text;

COMMENT ON COLUMN devices.revoked_cause IS
  'Why this device was revoked: ''cascade'' (its gateway was revoked — restorable) or ''deliberate'' (an operator revoked this device — never restorable). NULL = revoked before 0059, honestly unknown, treated as NOT restorable (S13.1 D5).';
