-- S15.1 (D14/D19 step 1) — a machine credential gets an OWNER.
--
-- ⛔ EVERY MACHINE PRINCIPAL SHIPPED BEFORE THIS WAS OWNERLESS, AND THAT IS THE DEFECT D14 RULED AGAINST.
-- An ownerless agent is outside the per-user device cap (which keys on user_id), outside any delegation link,
-- and still inside the org address pool: it costs the scarce thing and escapes both accountable ones.
--
-- ⚠ NULLABLE ON PURPOSE, AND ONLY FOR THE LENGTH OF THE MIGRATION. This is expand/contract step 1. A nullable
-- user_id IS the grandfather clause unless something refuses it, so the refusal lands in the SAME PR
-- (machine_bearer.go) rather than a later one — a NULL owner is refused AT USE, not merely un-set at rest.
-- Step 4 contracts to NOT NULL and cannot run until every row is assigned: that is an operator action with no
-- code date, a precondition nobody on this side controls rather than deferred work.
--
-- ⛔ ON DELETE RESTRICT, DELIBERATELY. Not CASCADE: deleting a user must not silently delete the machine
-- credentials they own — that is the S14.12 cascade class, and a GitOps operator vanishing because someone
-- offboarded its owner is exactly the failure this column exists to make visible. RESTRICT forces the
-- reassignment to be a decision.
ALTER TABLE machine_credentials
    ADD COLUMN user_id uuid REFERENCES users(id) ON DELETE RESTRICT;

-- The owner must belong to the credential's org. A cross-org owner would attribute a machine principal to
-- someone who cannot see it — enforced here rather than trusted to the handler, because the handler is one
-- caller and the table is the boundary.
CREATE INDEX IF NOT EXISTS machine_credentials_user_id_idx ON machine_credentials (user_id);
