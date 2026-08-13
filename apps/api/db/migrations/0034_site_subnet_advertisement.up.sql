-- S8.1 Slice 4: a site subnet is ADVERTISED (pending) and must be APPROVED before it propagates /
-- compiles into grants (D5: a compromised site gateway must not hijack routes by advertising subnets
-- it doesn't own — approval is the control-plane checkpoint; approved != reachable, ZT grants still
-- gate). Approval runs the ONE disjointness validator (D7). Existing Slice-2 subnets default to
-- 'pending' (they must be explicitly approved to take effect).
ALTER TABLE site_subnets ADD COLUMN status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved'));

-- Partial index so the compiler input (approved-only) + the pending-review list are both cheap.
CREATE INDEX site_subnets_status_idx ON site_subnets (status);
