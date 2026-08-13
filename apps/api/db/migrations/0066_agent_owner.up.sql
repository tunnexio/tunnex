-- S15.2 slice 1 — CAPTURE THE JOIN-TOKEN ISSUER, AND CARRY IT ONTO THE NODE.
--
-- ⛔ THIS SLICE IS FIRST BECAUSE IT STOPS AN ONGOING LOSS, NOT BECAUSE IT IS FOUNDATIONAL.
--
-- `IssueJoinToken(ctx, actor, orgID, nodeName)` already RECEIVES the human. It writes them to the audit log
-- and to nothing else, so every token minted before this migration discards its issuer to a table nobody
-- joins against — recoverable, if at all, only by parsing audit metadata. Every other slice in S15.2 costs
-- the same tomorrow as today. This one costs more every day it waits.
--
-- ⚠ THE COLUMN NAME IS `issued_by`, NOT `owner`, AND THAT IS THE WHOLE POINT (D-RANK2, ruled).
-- Enrolment is an agent redeeming a token UNATTENDED, so THE INSTALLER IS NOT CAPTURABLE BY CONSTRUCTION.
-- The issuer is the only fact that exists at a moment a human is present. A column called `owner` here would
-- claim knowledge of who installed the agent; `issued_by` claims only what happened.
--
-- ⛔ NULLABLE, AND DELIBERATELY SO — the expand half of expand/contract. Tokens minted before this migration
-- have no issuer and never will; a NOT NULL here would refuse to migrate a live database. The contract to
-- NOT NULL is a later story's problem, and S15.1's step 4 is the standing reminder that it is an OPERATOR
-- action with no code date.
ALTER TABLE node_join_tokens
    ADD COLUMN issued_by uuid REFERENCES users (id) ON DELETE SET NULL;

-- ⛔ `ON DELETE SET NULL` HERE, AND IT IS NOT THE SAME QUESTION AS D26.
-- A join token is a spent record of an act. If the issuing user is ever deleted, the token should lose the
-- name and SURVIVE — the enrolment it authorised still happened, and destroying the record of it would be
-- destroying history to tidy a foreign key. Contrast `nodes.owner_user_id` below, where the same choice is
-- genuinely open and is HELD as D26.

-- The owner, carried onto the node at enrolment.
--
-- ⚠ NOT `NOT NULL` YET: nodes enrolled before this migration have no owner, and D25 ruled that an agent must
-- NEVER be refused at use for want of one — it degrades and is flagged. Refusal happens at ENROLMENT, which
-- is a code gate on new nodes, not a schema gate on old ones.
--
-- ⛔ AND THE FK ACTION HERE IS `RESTRICT`, NOT `CASCADE` — the S15.1 choice, made against the S14.12 class.
-- This is a NEW column on `nodes`, so nothing is being changed out from under anyone: the divergence D26
-- holds is about `devices.user_id`, which S15.2 does not touch. Choosing CASCADE here to "match devices"
-- would be propagating the defect on the grounds that it is already present somewhere else.
ALTER TABLE nodes
    ADD COLUMN owner_user_id uuid REFERENCES users (id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS node_join_tokens_issued_by_idx ON node_join_tokens (issued_by);
CREATE INDEX IF NOT EXISTS nodes_owner_user_id_idx ON nodes (owner_user_id);
