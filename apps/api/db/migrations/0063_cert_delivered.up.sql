-- S13.1 D3, RULED: the redelivery carve-out narrows from "the caller proves the current key" to
-- "the certificate this control plane last issued was NEVER DELIVERED".
--
-- WHY THE FIRST PREDICATE WAS WRONG, recorded because the paper carries the failed attempt and not only the fix.
-- provesCurrentKey authorized any caller holding the recorded private key — including one holding it while the
-- gateway is RUNNING. RekeyNode replaces cert_serial, and the agent channel resolves the presented certificate
-- against exactly that column, so exercising it against a live node DISPLACED the running gateway: 401
-- unknown_agent on its next request. It needed only the private key, never the certificate, so a key stolen
-- without its certificate — from a backup, a memory dump, a mis-scoped log — went from inert to immediately
-- usable. A live-node takeover through the gate built to refuse live nodes.
--
-- WHY THIS PREDICATE IS RIGHT. A running gateway's certificate has AUTHENTICATED, by definition — that is what
-- running means. So marking delivery on first use makes the live case vanish STRUCTURALLY rather than by a check
-- someone has to remember: there is no state in which a live node's current certificate is undelivered.
ALTER TABLE nodes ADD COLUMN cert_delivered_at timestamptz;

COMMENT ON COLUMN nodes.cert_delivered_at IS
  'When the CURRENT cert_serial was first seen authenticating on the agent channel. NULL = issued but never used, which is the only state the D3 redelivery carve-out authorizes. Cleared by RekeyNode in the same statement that replaces cert_serial (S13.1).';

-- THE BACKFILL IS NOT COSMETIC — WITHOUT IT THIS FIX IS ITSELF A FAIL-OPEN.
--
-- A new nullable column reads NULL for the entire existing fleet, and NULL means "never delivered". Shipping that
-- would open the carve-out for EVERY node in the field on the day it deploys: a fail-open introduced by the fix
-- for a fail-open, and one that announces itself nowhere.
--
-- Every active node with a certificate has authenticated to obtain and renew it, so `enrolled_at` is a sound
-- lower bound on delivery — and last_seen_at, where present, is the sharper one. Revoked rows are left NULL
-- deliberately: the gate refuses them before it ever reads this column, and inventing a delivery time for a
-- retired credential would be a fact nobody observed.
UPDATE nodes
SET cert_delivered_at = coalesce(last_seen_at, enrolled_at, now())
WHERE revoked_at IS NULL AND cert_serial IS NOT NULL;
