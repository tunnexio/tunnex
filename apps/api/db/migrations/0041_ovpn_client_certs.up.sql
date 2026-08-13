-- S9.1 Slice 2: issued OpenVPN client certificates. An OVPN client is an ORDINARY device
-- (D-S9.1-3, one shared address world) — this table records the CERT it was issued so the
-- S9.1 Slice 5 revocation full-sweep can build the CRL and find the serial (B2). The client
-- PRIVATE KEY is NEVER stored (D-S9.2-1: server-generated, streamed into the .ovpn once, then
-- discarded) — only the cert identity + binding + expiry live here.
CREATE TABLE ovpn_client_certs (
    id           uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    device_id    uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,   -- the OVPN device this cert binds to
    serial       text NOT NULL,                                             -- hex serial; IS the cert identity for the CRL
    common_name  text NOT NULL,
    not_after    timestamptz NOT NULL,                                      -- D-S9.2-2: 365d leaf; expiry => re-issue
    issued_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz                                                -- set by the Slice 5 full-sweep -> CRL
);

-- The serial is the CRL key: globally unique, one row per issued cert.
CREATE UNIQUE INDEX ovpn_client_certs_serial_key ON ovpn_client_certs (serial);
-- Active (un-revoked) certs per org — the CRL source and the "does this device have a live profile" read.
CREATE INDEX ovpn_client_certs_org_active_idx ON ovpn_client_certs (org_id) WHERE revoked_at IS NULL;
-- A device's certs — the revocation sweep joins here when a device is revoked (B2 parity).
CREATE INDEX ovpn_client_certs_device_idx ON ovpn_client_certs (device_id);
