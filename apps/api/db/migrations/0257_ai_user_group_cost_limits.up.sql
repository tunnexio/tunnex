-- AI-CATALOG-1: a shared daily USD soft threshold for a human user group.
-- Requires 0256 (RBAC-1, merged as #145).
CREATE TABLE ai_user_group_cost_limits (
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id uuid NOT NULL,
    -- NULL = no limit. The row is kept when the limit is removed so the
    -- revision only increases and a stale editor always conflicts.
    daily_usd_threshold double precision CHECK (daily_usd_threshold > 0 AND daily_usd_threshold <= 100000),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, group_id),
    FOREIGN KEY (group_id, org_id) REFERENCES user_groups (id, org_id) ON DELETE CASCADE
);
COMMENT ON TABLE ai_user_group_cost_limits IS 'Daily USD soft threshold shared by all members of a user group across its AI model grants. Observed spend since midnight UTC; concurrent calls can overshoot.';
CREATE TRIGGER set_updated_at BEFORE UPDATE ON ai_user_group_cost_limits
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
