-- S13.1 fold BATCH C: what revoke DESTROYED that restore has to put back (review pass 1 #8, #9, F3).
--
-- Revocation is a three-part act and restore reversed one third of it, asserting terminal values for a
-- heterogeneous set. The schema recorded WHY a device was revoked (0059) but not WHAT IT WAS — so restore had no
-- choice but to guess, and it guessed 'active' for every row.

-- #8. The status a cascade found the device in. Without it, restore promotes a device that was PENDING — never
-- approved by anyone — straight to active, silently bypassing the org's device-approval gate. NULL means the row
-- predates this column: honestly unknown, and the restore treats unknown as PENDING when the org gates approval,
-- because guessing 'active' is the bypass and guessing 'pending' costs an operator one click.
ALTER TABLE devices ADD COLUMN revoked_prev_status text;

-- F3. The gateway the device's ISSUED CONFIG baked. Symmetric with provisioned_ip (0060) and recorded at the same
-- moment, for the same reason: the config embeds `PublicKey` and `Endpoint` of a specific gateway, so a device
-- that is re-homed holds a config naming a gateway that will never serve it — and needs_reexport compared the
-- address and the routes and NOT the gateway, so that device rendered perfectly fresh while being unusable.
ALTER TABLE devices ADD COLUMN provisioned_node_id uuid;

COMMENT ON COLUMN devices.provisioned_node_id IS
  'The gateway whose endpoint + public key this device''s ISSUED config baked. Compared against node_id at read time to derive needs_reexport for STATIC exports (S13.1 review fold F3).';

-- #9. Revoking a node revokes its devices AND their OpenVPN client certificates AND rebuilds the CRL — one act,
-- three parts. Restore reversed only the first, so an OVPN device came back `active` with its certificate still
-- revoked and still on the org CRL: control plane green, data plane refusing, operator told it succeeded.
--
-- The cause mirrors devices.revoked_cause exactly, and for the same reason: a certificate revoked DELIBERATELY
-- (an operator retiring one credential) must never be revived by a gateway rebuild, and the two cases are
-- indistinguishable without recording which is which.
ALTER TABLE ovpn_client_certs ADD COLUMN revoked_cause text
  CHECK (revoked_cause IS NULL OR revoked_cause IN ('deliberate', 'cascade'));
