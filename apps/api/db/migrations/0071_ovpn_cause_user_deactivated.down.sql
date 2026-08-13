-- ⚠ THE DOWN MUST CLEAR THE NEW CAUSE BEFORE NARROWING THE CHECK, or the constraint cannot be re-added
-- against rows already carrying it. Those certs stay REVOKED — dropping a cause is not un-revoking a
-- credential, and a rollback must never hand access back.
UPDATE ovpn_client_certs SET revoked_cause = 'deliberate' WHERE revoked_cause = 'user_deactivated';
ALTER TABLE ovpn_client_certs DROP CONSTRAINT ovpn_client_certs_revoked_cause_check;
ALTER TABLE ovpn_client_certs ADD CONSTRAINT ovpn_client_certs_revoked_cause_check
  CHECK (revoked_cause IS NULL OR revoked_cause IN ('deliberate', 'cascade'));
