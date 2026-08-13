-- S15.3 — THE MARKER. **THE OPERATOR'S DECLARATION OF WHAT THEY ARE ENROLLING.**
--
-- ⛔ WHY IT EXISTS: until now, `allocateAgentDevice` ran on `tok.IssuedBy.Valid` alone — so EVERY gateway
-- enrolled with an issuer-carrying token acquired a `kind='agent'` device row. Not agents. Every gateway.
-- The product had no way to say which kind of thing was being enrolled, so the surface could not either.
--
-- ⭐ CAPTURED AT THE SAME INSTANT AS THE ISSUER, because it is the same act: minting a join token is where
-- an operator says both WHO is accountable and WHAT is being brought online. The flow already carried the
-- first fact; it gains the second at no extra ceremony.
ALTER TABLE node_join_tokens
    ADD COLUMN enrols_kind text NOT NULL DEFAULT 'gateway'
        CHECK (enrols_kind IN ('gateway', 'agent'));

-- ⛔ NOT NULL WITH A 'gateway' DEFAULT — **ABSENCE MUST BE THE CLOSED STATE.**
--
-- A nullable marker read as "agent" would be the same fail-open one column over: every token that predates
-- this migration, and every future caller that forgets the field, would silently mint an agent. The default
-- is the ordinary thing; declaring an agent is the deliberate act.

-- Carried onto the node at enrolment, the same way `issued_by` becomes `owner_user_id`.
--
-- ⛔ NULLABLE HERE, AND THE NULL IS A REAL STATE, NOT A GAP: **UNDETERMINED.** A node enrolled before this
-- migration is neither an agent nor confirmed-not-an-agent — the fact was never recorded and CANNOT BE
-- RECOVERED, because the token that would have carried it is consumed and its intent was never asked for.
--
-- ⚠ THIS IS A STATE THE SURFACE MUST RENDER, NOT A BLANK. An undetermined node rendered as "not an agent"
-- asserts a fact nobody has; rendered as "agent" repeats the defect this migration fixes.
ALTER TABLE nodes
    ADD COLUMN enrolled_kind text
        CHECK (enrolled_kind IS NULL OR enrolled_kind IN ('gateway', 'agent'));

CREATE INDEX IF NOT EXISTS nodes_enrolled_kind_idx ON nodes (enrolled_kind) WHERE enrolled_kind = 'agent';
