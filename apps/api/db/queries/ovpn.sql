-- S9.1 Slice 2: OpenVPN client-cert records. The issuance path records the cert identity so the
-- Slice 5 revocation full-sweep + CRL have their source (B2). The private key is never stored.

-- name: InsertOVPNClientCert :one
INSERT INTO ovpn_client_certs (org_id, device_id, serial, common_name, not_after)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: ListActiveOVPNClientCertsByOrg :many
-- The CRL source: every un-revoked, issued client cert for an org (Slice 5 builds the CRL from
-- the COMPLEMENT — revoked serials — but this read backs the "live profiles" surface).
SELECT * FROM ovpn_client_certs
WHERE org_id = $1 AND revoked_at IS NULL
ORDER BY issued_at;

-- name: ListRevokedOVPNSerialsByOrg :many
-- The CRL entries for an org: serials revoked and not yet past expiry (an expired cert need not
-- appear on the CRL — it's rejected on validity anyway). Slice 5 renders these into the CRL.
SELECT serial, not_after, revoked_at FROM ovpn_client_certs
WHERE org_id = $1 AND revoked_at IS NOT NULL AND not_after > now()
ORDER BY revoked_at;

-- name: RevokeOVPNClientCertsForDevice :many
-- The B2 sweep member: revoking a device revokes ALL its live OVPN certs, returning their serials
-- so the caller pushes the updated CRL to the gateway (one sweep with address-release + status-clear).
-- lint:cross-org — keyed by device_id inside the device-revoke transaction, which the caller has
-- already org-authorized (mirrors RevokeDevicesForNode); the device->org binding is verified upstream.
UPDATE ovpn_client_certs
SET revoked_at = now()
WHERE device_id = $1 AND revoked_at IS NULL
RETURNING serial;

-- name: GetOVPNServerCertForNode :one
-- lint:cross-org — keyed by node_id; the caller (DesiredState) already authorized the node via mTLS.
SELECT * FROM ovpn_server_certs WHERE node_id = $1;

-- name: InsertOVPNServerCert :one
INSERT INTO ovpn_server_certs (org_id, node_id, serial, cert_pem, sealed_key, not_after)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: BumpOVPNCRLNumber :one
-- Atomically ALLOCATE the next monotonic per-org CRL number (D-S9.5-1: per-org, never a global counter).
-- Concurrent rebuilds get DISTINCT numbers; the crl_pem is set immediately after by SetOVPNCRL for THIS
-- number, so the highest-numbered (latest) CRL wins. On first revocation the placeholder crl_pem is empty
-- for the microseconds until SetOVPNCRL runs — delivery treats an empty crl_pem as not-yet-ready.
INSERT INTO ovpn_crls (org_id, crl_pem, number) VALUES ($1, ''::bytea, 1)
ON CONFLICT (org_id) DO UPDATE SET number = ovpn_crls.number + 1
RETURNING number;

-- name: SetOVPNCRL :exec
-- Store the signed CRL for the number THIS rebuild allocated. WHERE number = $3 so a concurrent rebuild
-- that bumped past us (higher number, later revocation snapshot) is authoritative — our lower-numbered CRL
-- is simply not stored (the latest full-set CRL wins).
UPDATE ovpn_crls SET crl_pem = $2, updated_at = now() WHERE org_id = $1 AND number = $3;

-- name: GetOVPNCRLForOrg :one
-- The org's current signed CRL (delivery reads this; empty crl_pem = not-yet-ready, skip this tick).
SELECT crl_pem, number FROM ovpn_crls WHERE org_id = $1;

-- name: RevokeOVPNClientCertsForNode :many
-- The node-revoke sweep member: revoking a NODE revokes all its devices (RevokeDevicesForNode), so their
-- live OVPN client certs are revoked too (revoked_at), returning the affected orgs so the shared RebuildCRL
-- runs once per org. lint:cross-org — keyed by node_id inside the node-revoke transaction (org-authorized
-- upstream, mirrors RevokeDevicesForNode).
UPDATE ovpn_client_certs SET revoked_at = now(), revoked_cause = 'cascade'
WHERE device_id IN (SELECT id FROM devices WHERE node_id = $1 AND deleted_at IS NULL) AND revoked_at IS NULL
RETURNING org_id;

-- name: RestoreCascadeRevokedOVPNCertsForDevice :many
-- The third part of the act, reversed (review pass 1 #9). Revoking a node revokes its devices AND their OpenVPN
-- client certificates AND rebuilds the CRL. Restore reversed only the first, so an OVPN device came back `active`
-- with its certificate still revoked and still on the org CRL — control plane green, data plane refusing, and the
-- operator told it succeeded.
--
-- cause='cascade' ONLY, exactly like the device restore: a certificate an operator revoked deliberately is never
-- revived by a gateway rebuild. The predicate is repeated here rather than left to the caller, same as
-- RestoreCascadeRevokedDevice.
-- lint:cross-org — keyed by device_id, which the caller read from the org-scoped candidate set.
UPDATE ovpn_client_certs SET revoked_at = NULL, revoked_cause = NULL
WHERE device_id = $1 AND revoked_at IS NOT NULL AND revoked_cause = 'cascade'
RETURNING org_id, serial;

-- name: RevokeOVPNCertsForDeactivatedUser :many
-- ⛔ DEACTIVATION MUST REACH THE CRL, OR THE REFUSAL IS CONFIGURATIONAL ONLY.
--
-- Deactivating a user drops their devices out of the WG peer set and the OVPN CCD roster, and the agent
-- full-sweeps the stale CCD file — so `ccd-exclusive` refuses the client. That chain is real, and it is ONE
-- MECHANISM, living in the AGENT. The certificate itself stays cryptographically valid, so a gateway whose
-- `server.conf` lost `ccd-exclusive` would admit a deactivated user's OpenVPN client on cert alone.
--
-- > **A REFUSAL THAT DEPENDS ENTIRELY ON A CONFIG FLAG ON A REMOTE BOX IS NOT DEFENCE IN DEPTH.** The
-- > control plane can make it cryptographic, and then both halves have to fail for access to survive.
--
-- ⚠ CAUSE `user_deactivated`, NOT `cascade`, and the distinction is the one this table already draws: a
-- cascade cert is revived by a gateway restore, and these must not be — they come back when the USER does,
-- and by nothing else. A deliberately-revoked cert is revived by neither.
-- lint:cross-org — keyed by user + org inside the org-scoped deactivate transaction.
UPDATE ovpn_client_certs c SET revoked_at = now(), revoked_cause = 'user_deactivated'
WHERE c.org_id = @org_id
  AND c.device_id IN (SELECT d.id FROM devices d WHERE d.user_id = @user_id AND d.org_id = @org_id AND d.deleted_at IS NULL)
  AND c.revoked_at IS NULL
RETURNING c.serial;

-- name: RestoreOVPNCertsForReactivatedUser :many
-- ⛔ THE SYMMETRIC HALF, AND SHIPPING WITHOUT IT WOULD BE A ONE-WAY DOOR. Reactivation restores memberships,
-- sessions and the peer set; if the certificate stayed revoked the user would come back `active` everywhere
-- while their OpenVPN client was refused by the CRL — control plane green, data plane refusing, and the
-- operator told it succeeded. That exact defect is on record for the node-restore path (review pass 1 #9).
--
-- ⚠ `user_deactivated` ONLY. A cert revoked deliberately, or cascaded by a gateway revoke, is NOT revived by
-- a user coming back — reactivation reverses its own act and no one else's.
-- lint:cross-org — keyed by user + org inside the org-scoped reactivate transaction.
UPDATE ovpn_client_certs c SET revoked_at = NULL, revoked_cause = NULL
WHERE c.org_id = @org_id
  AND c.device_id IN (SELECT d.id FROM devices d WHERE d.user_id = @user_id AND d.org_id = @org_id AND d.deleted_at IS NULL)
  AND c.revoked_at IS NOT NULL AND c.revoked_cause = 'user_deactivated'
RETURNING c.serial;
