-- S7.5.4 per-user + temporary policy grants. Two ORTHOGONAL extensions to
-- policy_rules (a rule can be per-user, temporary, both, or neither):
--   1. a rule's SUBJECT can be a single USER (src_kind='user'), not just a group;
--   2. a rule can EXPIRE at a set time (expires_at), a temporary grant.
-- The compiled artifact stays IP-ONLY: a per-user subject resolves to that user's
-- device /32s CP-side, exactly like a group — NO enforcement wire-version bump.

-- src_kind mirrors dst_kind: exactly one of src_group_id / src_user_id is set.
-- Existing rows are all group-subject (the pre-S7.5.4 model), so default 'group'.
ALTER TABLE policy_rules ADD COLUMN src_kind text NOT NULL DEFAULT 'group'
    CHECK (src_kind IN ('group', 'user'));

-- src_group_id was NOT NULL (group-only). A user-subject rule has it NULL.
ALTER TABLE policy_rules ALTER COLUMN src_group_id DROP NOT NULL;

-- src_user_id: the per-user subject. The COMPOSITE FK to memberships (org_id,user_id)
-- is load-bearing exactly as group_members' is: it refuses a non-member AND — the
-- critical part — CASCADES on membership removal, so revoking an org member instantly
-- deletes their per-user grants (a departed member must not keep scoped access). The
-- wire freshness of that delete rides the S7.2 member-removal recompile trigger (the
-- F1 committed-removal-must-push law — see docs/S7.5.4-decisions.md D1 rider).
-- NULL for group rules (MATCH SIMPLE: a NULL column skips the FK check).
ALTER TABLE policy_rules ADD COLUMN src_user_id uuid;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_user_fk
    FOREIGN KEY (org_id, src_user_id) REFERENCES memberships (org_id, user_id) ON DELETE CASCADE;

-- Exactly one source subject, matching src_kind (mirrors the dst_kind CHECK).
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_check CHECK (
    (src_kind = 'group' AND src_group_id IS NOT NULL AND src_user_id IS NULL)
 OR (src_kind = 'user'  AND src_user_id  IS NOT NULL AND src_group_id IS NULL));

-- expires_at: NULL = permanent (every existing rule); set = a temporary grant that
-- lapses at this instant. The compiler snapshot EXCLUDES expired rules (correctness
-- backstop); a sweeper pushes the recompile promptly at expiry (S7.5.4 slice 2).
-- Window-EXTENSIBLE in place (UPDATE expires_at), never delete+recreate.
ALTER TABLE policy_rules ADD COLUMN expires_at timestamptz;
-- Partial index so the sweeper cheaply finds temporary rules due to lapse.
CREATE INDEX policy_rules_expires_idx ON policy_rules (expires_at) WHERE expires_at IS NOT NULL;

-- The dedup uniqueness was keyed on src_group_id (group-only). Widen to src-kind-aware
-- partial indexes so a per-user rule dedups on src_user_id (a NULL src_group_id would
-- make every user rule "distinct" under the old index). One grant per (src subject, dst)
-- pair regardless of expiry — a duplicate create is a 409; extend moves the window.
DROP INDEX policy_rules_resource_uniq;
DROP INDEX policy_rules_group_uniq;
CREATE UNIQUE INDEX policy_rules_group_resource_uniq ON policy_rules (org_id, src_group_id, dst_resource_id)
    WHERE src_kind = 'group' AND dst_kind = 'resource';
CREATE UNIQUE INDEX policy_rules_group_group_uniq ON policy_rules (org_id, src_group_id, dst_group_id)
    WHERE src_kind = 'group' AND dst_kind = 'group';
CREATE UNIQUE INDEX policy_rules_user_resource_uniq ON policy_rules (org_id, src_user_id, dst_resource_id)
    WHERE src_kind = 'user' AND dst_kind = 'resource';
CREATE UNIQUE INDEX policy_rules_user_group_uniq ON policy_rules (org_id, src_user_id, dst_group_id)
    WHERE src_kind = 'user' AND dst_kind = 'group';
