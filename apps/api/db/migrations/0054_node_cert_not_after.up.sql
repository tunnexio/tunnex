-- S11 walk WF-S11-6: record WHEN the certificate we issued expires.
--
-- The CP has always stored cert_serial (the agent's identity) but never the expiry it minted. That absence is
-- why a bricked gateway was indistinguishable from a merely-quiet one: with no expiry on record, "this agent
-- cannot reconnect" could only be INFERRED from silence, and silence has many causes.
--
-- Storing it makes the state a DERIVATION from the CP's own signing record rather than a guess, and — the part
-- that matters operationally — it can be evaluated BEFORE the agent tries and fails. A gateway that has been
-- offline for 40 hours is eight hours from being unrecoverable; that is worth saying while it is still
-- actionable.
--
-- Nullable and additive by design: pre-existing rows have no recorded expiry, which is honest (we do not know)
-- and is treated as unknown rather than as expired. Backward-compatible for the rolling-upgrade contract (D1) —
-- the previous CP version simply never reads the column.
ALTER TABLE nodes ADD COLUMN cert_not_after timestamptz;

COMMENT ON COLUMN nodes.cert_not_after IS
  'Expiry of the currently-issued agent cert, stamped at enroll/renew. NULL = issued before this column existed (unknown, not expired). Past = the agent CANNOT reconnect: /agent/renew requires the cert that expired (S11 WF-S11-6).';
