-- S13.1 D10: a SECOND identifier for re-key, so a LOST RESPONSE cannot brick a gateway permanently.
--
-- THE FAILURE THIS EXISTS FOR. Re-key commits the new serial and the new public key, then answers. If the answer is
-- lost — a dropped connection, an ingress timeout, an agent restart between commit and write — the control plane
-- holds a serial the agent never received. The agent retries with the serial from its stored (expired) certificate,
-- which no row carries any more, so every future attempt is refused and the ONLY recovery is an operator minting a
-- join token: a NEW node, its site binding gone, its devices needing re-issue. A single dropped packet costing a
-- gateway its identity.
--
-- WHY A FINGERPRINT RATHER THAN A GRACE WINDOW ON THE PREVIOUS SERIAL. A grace window reintroduces a TIME BOUND of
-- exactly the kind D3 spent this epic removing — recovery would work for an hour and then not, for reasons invisible
-- to the operator. The key fingerprint is material the control plane ALREADY records (0057) and the agent already
-- holds, so this adds a lookup key, not a new secret. A public-key fingerprint is at least as unguessable as a
-- serial, which was D9's whole criterion for choosing the serial over the node name.
--
-- GENERATED, NOT WRITTEN. The column is derived by the DATABASE from cert_public_key, so it cannot drift from the
-- key it names: there is no application path that can update one without the other. A NULL key (a node enrolled
-- before 0057) yields a NULL fingerprint, which matches nothing — those nodes recover by join token, as D1(a) always
-- said.
--
-- NOT UNIQUE, DELIBERATELY. Nothing today prevents two nodes from being enrolled with the same public key (copy a
-- state directory, enrol with a second token), so a UNIQUE index would turn a lookup ambiguity into a MIGRATION
-- FAILURE on any fleet where that already happened, and later into a confusing enrolment refusal. Instead the
-- ambiguity is handled where it is observed: the lookup reads up to TWO rows and REFUSES if more than one matches
-- (nodes.resolveRekeyIdentity). Ambiguity at the moment identity is being trusted must fail closed, and it does.
ALTER TABLE nodes
  ADD COLUMN cert_key_fingerprint text
  GENERATED ALWAYS AS (encode(sha256(decode(cert_public_key, 'base64')), 'hex')) STORED;

COMMENT ON COLUMN nodes.cert_key_fingerprint IS
  'SHA-256 of cert_public_key''s SPKI DER, lowercase hex. GENERATED from the key so the two cannot drift. The second re-key identifier (S13.1 D10); NOT unique — the lookup refuses on multiple matches.';

-- Plain, not unique — see above. Covers the only query that reads it.
CREATE INDEX nodes_cert_key_fingerprint_idx ON nodes (cert_key_fingerprint)
  WHERE cert_key_fingerprint IS NOT NULL;

-- The challenge is bound to the IDENTIFIER it was issued for, whichever kind that is. Without the kind, a nonce
-- issued for a serial could be submitted with a fingerprint that happened to be the same string — impossible in
-- practice, and the sort of "impossible" that stops being true when a format changes.
--
-- EXPAND, NOT RENAME. The first draft renamed cert_serial to identifier and TestMigrationsAreBackwardCompatible-
-- ForOneVersion refused it: during a rolling upgrade the previous control-plane version runs against this schema,
-- and a renamed column simply stops existing for it (S11 D1). So the new columns are ADDED, the old one stays for
-- one release with its NOT NULL dropped (a fingerprint is not a serial and must never be written there), and the
-- CONTRACT — dropping cert_serial once no shipped version reads it — is a later migration.
--
-- The new code also writes cert_serial for SERIAL-kind challenges (a transitional shim, named as such in
-- CreateRekeyChallenge), so a previous-version replica mid-roll can still consume challenges a new replica issued.
-- Without that, re-key would degrade during exactly the window an operator is most likely to be recovering a
-- gateway. Write-only duplication for one release: nothing reads cert_serial in this version.
ALTER TABLE node_rekey_challenges ADD COLUMN identifier text;
ALTER TABLE node_rekey_challenges ADD COLUMN identifier_kind text NOT NULL DEFAULT 'cert_serial'
  CHECK (identifier_kind IN ('cert_serial', 'key_fingerprint'));
ALTER TABLE node_rekey_challenges ALTER COLUMN cert_serial DROP NOT NULL;

-- Existing rows are serial-kind by construction (they predate the second identifier) and live at most an hour.
UPDATE node_rekey_challenges SET identifier = cert_serial WHERE identifier IS NULL;
