-- S13.1 D7: record the PUBLIC KEY of the certificate we issue, so a returning gateway can prove possession of it.
--
-- WHY THE CP NEEDS THIS. Gateway recovery authenticates a returning agent by PROOF OF POSSESSION of its existing
-- keypair (D1 ruled (c)): the agent signs a server nonce plus its new CSR with the private key it still holds, and
-- the CP verifies that signature. Verification requires a public key the CP holds — and it held none. `cert_serial`
-- identifies a certificate but carries no key material, and the certificate itself was never stored.
--
-- nodes.wg_public_key CANNOT SUBSTITUTE. WireGuard keys are X25519, for Diffie-Hellman; they cannot produce
-- signatures at all. That is arithmetic, not policy — no amount of protocol design makes a DH key sign.
--
-- SPKI DER, base64-encoded: the form x509.ParsePKIXPublicKey reads back, so verification never guesses an
-- encoding. Taken from the CSR, which is by construction the key the issued certificate binds.
--
-- COVERAGE IS A STATED PRODUCT LIMITATION, not a footnote. This column is NULL for every node enrolled before it
-- shipped, and PoP cannot recover a node whose key the CP does not know — those fall back to the join token (the
-- manual path). Crucially it is stamped on RENEWAL as well as enrolment, so a running fleet self-heals into
-- coverage within one renewal cycle (~24h at half-life of a 48h certificate). Only already-dead nodes stay
-- token-only — and those are precisely the ones a human is already attending to.
--
-- Nullable and additive: backward-compatible for the rolling-upgrade contract (D1 of EPIC 11), and NULL means
-- honestly-unknown rather than a fabricated value.
ALTER TABLE nodes ADD COLUMN cert_public_key text;

COMMENT ON COLUMN nodes.cert_public_key IS
  'base64(SPKI DER) of the public key bound by the current agent certificate, stamped at enroll and renew. Verification material for proof-of-possession re-key (S13.1 D7). NULL = enrolled before 0057 and not yet renewed: PoP cannot recover that node, only a join token can.';
