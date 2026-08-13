-- S9.1 Slice 5 (D-S9.5-1): the per-org OpenVPN CRL, signed by the one shared client CA. PER-ORG (not one
-- global CRL) — a global CRL delivered to every gateway would leak each org's revoked-serial count +
-- issuance cadence to every other org's gateways (a cross-tenant info leak; org-scoped like every tenant
-- row). Rebuilt WHOLE on every revoke (never appended) + on a schedule inside nextUpdate (never expires —
-- an expired CRL can fail-OPEN). `number` is the monotonic PER-ORG CRL sequence (never a global counter,
-- which would re-introduce the cross-org signal). crl_pem is a valid signed CRL (possibly EMPTY — an org
-- with zero revocations still delivers a real CRL, never a missing file: crl-verify is always-on).
CREATE TABLE ovpn_crls (
    org_id     uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    crl_pem    bytea       NOT NULL,
    number     bigint      NOT NULL,   -- monotonic per-org CRL sequence number
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- updated_at auto-maintenance (convention: every updated_at column has the trigger).
CREATE TRIGGER set_updated_at BEFORE UPDATE ON ovpn_crls
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
