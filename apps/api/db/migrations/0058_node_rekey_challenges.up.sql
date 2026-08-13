-- S13.1 D9: single-use, short-lived challenges for proof-of-possession re-key.
--
-- WHY A NONCE AT ALL. The proof is bound to the new CSR, which stops a captured proof being paired with an
-- attacker's own CSR. Binding alone still permits replaying the ENTIRE captured request, so the challenge is
-- server-issued, recorded here, and consumed exactly once.
--
-- ISSUED WITHOUT CHECKING THE SERIAL EXISTS — deliberately. The challenge endpoint must leak nothing about whether
-- a certificate serial is known to this control plane; a challenge that succeeded only for real serials would be an
-- enumeration oracle. So a nonce is minted and recorded for whatever serial is asked about, and the SUBMIT step is
-- where a nonexistent serial fails — with the same uniform refusal as a wrong key or a live node. Flood protection
-- is the endpoint's rate limit, not this table's shape.
--
-- Keyed on the CERT SERIAL rather than the node name (D9): node names are guessable, serials are not.
CREATE TABLE node_rekey_challenges (
    nonce       bytea       PRIMARY KEY,      -- 32 random bytes; the value the agent signs over
    cert_serial text        NOT NULL,         -- the serial the challenge was issued FOR; bound at submit time
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz                   -- non-null = spent; a second attempt with it must fail
);

-- Sweep index: expired-and-unconsumed rows are garbage, and this table is written by an unauthenticated endpoint,
-- so it must be cheap to prune.
CREATE INDEX node_rekey_challenges_expires_idx ON node_rekey_challenges (expires_at);
