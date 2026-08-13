-- 0007 domain_claims (S2.5) — per-org DNS-verified email-domain capture.
--
-- Verification is a state machine (pending -> verified) tracked by verified_at.
-- Uniqueness is enforced at the DB, and only VERIFIED claims reserve a domain
-- globally (a partial unique index), so an unverified claim can never squat a
-- domain and block its rightful owner.
CREATE TABLE domain_claims (
    id                 uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id             uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain             citext NOT NULL,
    verification_token text NOT NULL,   -- random per-claim (tunnex-verify=<token>)
    verified_at        timestamptz,     -- NULL = pending
    last_checked_at    timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

-- One claim per (org, domain).
CREATE UNIQUE INDEX domain_claims_org_domain_key ON domain_claims (org_id, domain);

-- Global uniqueness applies ONLY to verified claims: unverified claims do not
-- reserve the domain, so squatting is impossible and the race resolves at the
-- index (the second org to verify the same domain loses).
CREATE UNIQUE INDEX domain_claims_verified_domain_key
    ON domain_claims (domain) WHERE verified_at IS NOT NULL;

CREATE INDEX domain_claims_org_id_idx ON domain_claims (org_id);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON domain_claims
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
