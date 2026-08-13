-- A third revocation cause: the certificate's OWNER was deactivated.
--
-- ⛔ WHY IT IS ITS OWN CAUSE AND NOT `cascade`. The cause is not a label, it is the answer to "what revives
-- this?" — 0062 introduced it for exactly that reason. A `cascade` cert is revived when the GATEWAY that
-- cascaded it is restored; a `deliberate` cert is revived by nothing. Neither is right here: this cert must
-- come back when the USER does, and by nothing else.
--
-- Sharing `cascade` would have let a gateway restore silently un-revoke a deactivated user's credential —
-- an access grant handed back by an operation about a different subject entirely.
ALTER TABLE ovpn_client_certs DROP CONSTRAINT ovpn_client_certs_revoked_cause_check;
ALTER TABLE ovpn_client_certs ADD CONSTRAINT ovpn_client_certs_revoked_cause_check
  CHECK (revoked_cause IS NULL OR revoked_cause IN ('deliberate', 'cascade', 'user_deactivated'));

COMMENT ON COLUMN ovpn_client_certs.revoked_cause IS
  'What revoked this cert, which determines what may revive it: deliberate (nothing revives it), '
  'cascade (a gateway restore), user_deactivated (that user being reactivated, and only that).';
