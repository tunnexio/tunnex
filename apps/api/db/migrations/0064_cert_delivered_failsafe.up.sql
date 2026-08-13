-- S13.1 D3 condition 2, EXTENDED TO NEW ROWS. Same defect, one step later in the lifecycle.
--
-- 0063 backfilled the existing fleet because a nullable column reads NULL fleet-wide and NULL meant UNDELIVERED —
-- the state that opens the redelivery carve-out. The backfill fixed the rows that existed. It did nothing for the
-- rows created AFTERWARDS.
--
-- CreateNode (db/queries/nodes.sql) inserts org_id, name, cert_serial, agent_version, cert_not_after and
-- cert_public_key — and not cert_delivered_at. So EVERY newly enrolled node read undelivered while holding a
-- valid certificate, on every replica, old or new. Not a rolling-upgrade artifact: the steady-state enrolment
-- path. And during a roll it is identical, because an old replica runs the same INSERT.
--
-- THE ENCODING IS THE FIX. A nullable timestamp cannot express this safely: absence has to mean "delivered"
-- (closed) for any writer that does not know the column, while re-key still needs to express "not delivered"
-- (open). A NOT NULL boolean DEFAULTING TO TRUE does exactly that — an INSERT that never mentions it lands in the
-- CLOSED state, and only RekeyNode opens it, explicitly, in the same statement that replaces the serial.
--
-- NOT NULL DEFAULT now() on the timestamp would have failed the second half: RekeyNode must record "never
-- delivered", and NOT NULL forbids the NULL that meant it.
ALTER TABLE nodes ADD COLUMN cert_delivered boolean NOT NULL DEFAULT true;

-- Carry 0063's observation across: rows it could not vouch for stay closed, which is the safe direction.
UPDATE nodes SET cert_delivered = (cert_delivered_at IS NOT NULL) WHERE revoked_at IS NULL;

COMMENT ON COLUMN nodes.cert_delivered IS
  'FALSE only while the CURRENT cert_serial has never authenticated — the only state the D3 redelivery carve-out authorizes. DEFAULT TRUE so any writer that does not know this column (an older control-plane replica mid-roll, or CreateNode) lands in the CLOSED state (S13.1).';

-- cert_delivered_at stays as the human-readable observation (when, not whether). It is no longer the gate input,
-- so its NULL-for-new-rows behaviour is now harmless.
