-- S9.1 D-S9.5-OPTIN: OpenVPN is unlock-then-opt-in — OFF by default at the org level (owner opt-in,
-- like device_approval). OFF means NOTHING OVPN exists: the export endpoint refuses, the UI offers no
-- OVPN device type, and (crucially) the platform CA is not even generated until the first export in an
-- opted-in org (the CA loads lazily, never at boot). Default false → an OVPN-disabled deployment is
-- byte-identical to today.
ALTER TABLE organizations ADD COLUMN ovpn_enabled boolean NOT NULL DEFAULT false;
