-- S9.1 Slice 4 (D-S9.4-MODEL): an OpenVPN client is a DEVICE ROW with a transport tag, NOT a
-- parallel entity. The compiler already keys device subjects by /32 + owner + node transport-
-- agnostically (B1), so an OVPN client that is a device inherits every proven property for free:
-- grants, the full-sweep revocation, the S7.3 per-user cap + pool accounting, the approval gate,
-- audit attribution. The tag exists ONLY so the roster + export path can FILTER (which devices are
-- OpenVPN) — NEVER so the policy engine can distinguish (transport never reaches policy.Device or
-- AllowEntry; the Slice-1 field-set checkpoint guards that).
ALTER TABLE devices ADD COLUMN transport text NOT NULL DEFAULT 'wireguard'
    CHECK (transport IN ('wireguard', 'openvpn'));
