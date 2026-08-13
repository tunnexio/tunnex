-- S13.1 Slice 6: snapshot the tunnel address a device's issued config BAKED, so a later change is detectable.
--
-- WHY IT DID NOT EXIST, AND WHY THE GAP WAS INVISIBLE. `needs_reexport` is derived at read time by comparing
-- provisioned_ranges (what the profile baked) against the org's CURRENT routed ranges. There was no equivalent for
-- the ADDRESS, so `assigned_ip` had nothing to compare against — a device whose address changed rendered EXACTLY as
-- clean as one that kept it.
--
-- Slice 5 made that concrete: cascade-restore can bring a device back on a FRESH address when a live device took the
-- original, and every such user's WireGuard config embeds the old address and will not connect until re-imported.
-- The audit event recorded it (device.restored_readdressed); the device surface could not.
--
-- SYMMETRIC WITH provisioned_ranges by design: snapshot-at-issuance versus live-value, compared at read time, with
-- no stored staleness flag to drift out of date.
--
-- RECORDED FOR EVERY PROVISIONING MODE, not just static — which is the OTHER half of the gap. The ranges snapshot is
-- static-only because only a static export bakes routes; a managed (desktop-client) device polls them. But EVERY
-- issued config embeds an interface address, managed included, so a managed device whose address changed is just as
-- stale and was silently excluded from the signal. Its user would have discovered it by failing to connect.
--
-- NULL = no config issuance recorded this (rows predating 0060). Honestly unknown, and therefore NOT reported as
-- stale: claiming staleness on absent evidence is the mirror of missing it.
ALTER TABLE devices ADD COLUMN provisioned_ip text;

COMMENT ON COLUMN devices.provisioned_ip IS
  'The tunnel address baked into this device''s ISSUED config, snapshotted at issuance for every provisioning mode. Compared against assigned_ip at read time to derive needs_reexport. NULL = predates 0060, honestly unknown, not reported stale (S13.1 Slice 6).';
