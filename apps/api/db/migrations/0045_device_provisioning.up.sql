-- S9.1 Part-2 (RULED): record HOW a device was provisioned, for legibility. A profile exported as a
-- file/QR is consumed by a NON-POLLING client, so its routed ranges are BAKED at export time and go
-- stale silently when a subnet is later added (polling clients get it in ~30s; static ones never do).
-- Recording provisioning_mode + the ranges snapshot lets the UI answer "these static-provisioned
-- devices don't include the new subnet — re-export" (the never-silently-broken law on routing truth).
-- Derives from the EXPORT PATH, not a live attribute: provisioning_mode is an immutable record of how
-- the device was provisioned, never a flag someone maintains.
ALTER TABLE devices ADD COLUMN provisioning_mode text NOT NULL DEFAULT 'managed'
    CHECK (provisioning_mode IN ('managed', 'static'));
-- The approved ranges snapshot baked into a static profile at export (JSON array of CIDRs). NULL for
-- managed (polling) devices — they carry no baked ranges. The stale-profile surface diffs this against
-- the org's CURRENT routed ranges.
ALTER TABLE devices ADD COLUMN provisioned_ranges jsonb;
