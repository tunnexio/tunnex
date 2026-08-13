-- S15.3 — an AGENT can be a policy SOURCE.
--
-- ⛔ AN AGENT IS A PEER, SO A GRANT NAMES A DEVICE. Naming the NODE would grant every device homed on that
-- gateway — a grant to one agent silently becoming a grant to everything behind it.
--
-- ⛔ WITHOUT THIS, THE AGENT SURFACE IS UNGRANTABLE. The screen says an agent "reaches only what it is
-- granted", and the Add-rule dialog offered Group / User / Site / CIDR — no way to name an agent. The
-- capability existed and the operator could not reach it: the verb-census class, on the one screen this
-- epic built.
--
-- ⚠ THIS IS POLICY INPUT, NOT A DESCRIPTIVE MARKER. It reaches the compiler deliberately — a grant's
-- source must — and it resolves to the agent's own /32 exactly as a user-source resolves to that user's
-- device /32s. The S15.3 isolation gate is about `label`/`kind` (descriptions) never entering the
-- ENFORCEMENT PROJECTION; a source subject is the opposite kind of thing.
ALTER TABLE policy_rules ADD COLUMN src_device_id uuid REFERENCES devices (id) ON DELETE CASCADE;

-- ⚠ ON DELETE CASCADE, and it is the right action HERE: a grant whose source DEVICE is gone is not a grant
-- that should linger. Contrast nodes.owner_user_id (RESTRICT) — that protects a node from losing its
-- owner; this removes a rule that can no longer match anything.
CREATE INDEX IF NOT EXISTS policy_rules_src_device_id_idx ON policy_rules (src_device_id) WHERE src_device_id IS NOT NULL;

-- ⛔ THE EXACTLY-ONE-SOURCE CHECK MUST LEARN THE NEW KIND, OR THE COLUMN IS UNREACHABLE.
-- The existing CHECK enumerates every (kind, column) pair; a new kind not listed there is refused by the
-- database no matter what the API accepts. ⚠ Adding the column without the CHECK would have been a column
-- nothing could ever write — the dormant-machinery class, in a migration.
ALTER TABLE policy_rules DROP CONSTRAINT IF EXISTS policy_rules_src_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_kind_check
    CHECK (src_kind IN ('group','user','site','cidr','agent'));

ALTER TABLE policy_rules DROP CONSTRAINT IF EXISTS policy_rules_src_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_check CHECK (
    (src_kind = 'group' AND src_group_id IS NOT NULL AND src_user_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL AND src_device_id IS NULL)
 OR (src_kind = 'user'  AND src_user_id  IS NOT NULL AND src_group_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL AND src_device_id IS NULL)
 OR (src_kind = 'site'  AND src_site_id  IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_cidr IS NULL AND src_device_id IS NULL)
 OR (src_kind = 'cidr'  AND src_cidr     IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_site_id IS NULL AND src_device_id IS NULL)
 OR (src_kind = 'agent' AND src_device_id  IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL)
);
