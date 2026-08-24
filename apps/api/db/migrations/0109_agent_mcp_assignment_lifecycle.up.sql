-- S18: immutable MCP profile history and one active assignment per group.
ALTER TABLE agent_mcp_profiles
    ADD COLUMN archived_at timestamptz NULL;

ALTER TABLE agent_mcp_profile_assignments
    ADD COLUMN state text NOT NULL DEFAULT 'active'
        CHECK (state IN ('active','replaced','unassigned','quarantined')),
    ADD COLUMN ended_at timestamptz NULL,
    ADD COLUMN ended_by_user_id uuid NULL REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN quarantine_reason text NULL;

-- Quarantine both group duplicates and cross-group inheritance ambiguity,
-- including the same profile through two groups. Selecting a winner would
-- silently change runtime configuration.
WITH ambiguous_groups AS (
    SELECT org_id, agent_group_id
    FROM agent_mcp_profile_assignments
    GROUP BY org_id, agent_group_id
    HAVING count(*) > 1
), ambiguous_devices AS (
    SELECT m.org_id, m.device_id
    FROM agent_group_members m
    JOIN agent_mcp_profile_assignments a
      ON a.org_id = m.org_id AND a.agent_group_id = m.agent_group_id
    GROUP BY m.org_id, m.device_id
    HAVING count(a.id) > 1
), quarantined AS (
    UPDATE agent_mcp_profile_assignments a
       SET state = 'quarantined', ended_at = now(),
           quarantine_reason = 'legacy_mcp_assignment_ambiguity'
     WHERE EXISTS (SELECT 1 FROM ambiguous_groups x WHERE a.org_id = x.org_id AND a.agent_group_id = x.agent_group_id)
        OR EXISTS (
            SELECT 1 FROM agent_group_members m
            JOIN ambiguous_devices d ON d.org_id = m.org_id AND d.device_id = m.device_id
            WHERE m.org_id = a.org_id AND m.agent_group_id = a.agent_group_id
        )
    RETURNING a.org_id, a.agent_group_id
)
INSERT INTO audit_logs (org_id, actor_system, action, target_type, target_id, metadata)
SELECT DISTINCT org_id, 'migration:0109', 'agent_mcp_profile.ambiguity_quarantined',
       'agent_group', agent_group_id::text,
       jsonb_build_object('cause','legacy_mcp_assignment_ambiguity')
FROM quarantined;

CREATE UNIQUE INDEX agent_mcp_profile_one_active_group
    ON agent_mcp_profile_assignments (org_id, agent_group_id)
    WHERE state = 'active';

CREATE INDEX agent_mcp_profile_assignments_org_group_state_idx
    ON agent_mcp_profile_assignments (org_id, agent_group_id, state, assigned_at DESC);

-- Historical rows do not participate in inheritance conflict detection.
CREATE OR REPLACE FUNCTION agent_mcp_profile_one_per_agent() RETURNS trigger AS $$
DECLARE
    locked_device_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'agent_mcp_profile_assignments' THEN
        IF NEW.state <> 'active' THEN RETURN NEW; END IF;
        -- Serialize assignment and membership writes for one group before
        -- taking per-device locks; this closes empty-group races.
        PERFORM pg_advisory_xact_lock(
            hashtextextended(NEW.org_id::text || ':group:' || NEW.agent_group_id::text, 0)
        );
        -- Acquire every affected device lock in a stable order. This closes
        -- assignment/member-write races without introducing a lock-order
        -- deadlock when a group has many members.
        FOR locked_device_id IN
            SELECT m.device_id
            FROM agent_group_members m
            WHERE m.org_id = NEW.org_id AND m.agent_group_id = NEW.agent_group_id
            ORDER BY m.device_id
        LOOP
            PERFORM pg_advisory_xact_lock(
                hashtextextended(NEW.org_id::text || ':' || locked_device_id::text, 0)
            );
        END LOOP;
        IF EXISTS (
            SELECT 1
            FROM agent_group_members target_member
            JOIN agent_mcp_profile_assignments existing
              ON existing.org_id = target_member.org_id AND existing.state = 'active'
            JOIN agent_group_members existing_member
              ON existing_member.org_id = existing.org_id
             AND existing_member.agent_group_id = existing.agent_group_id
            WHERE target_member.org_id = NEW.org_id
              AND target_member.agent_group_id = NEW.agent_group_id
              AND existing_member.device_id = target_member.device_id
              AND existing.agent_group_id <> NEW.agent_group_id
        ) THEN RAISE EXCEPTION 'an agent may have only one MCP profile'; END IF;
    ELSE
        PERFORM pg_advisory_xact_lock(
            hashtextextended(NEW.org_id::text || ':group:' || NEW.agent_group_id::text, 0)
        );
        PERFORM pg_advisory_xact_lock(hashtextextended(NEW.org_id::text || ':' || NEW.device_id::text, 0));
        IF EXISTS (
            SELECT 1 FROM agent_mcp_profile_assignments incoming
            JOIN agent_mcp_profile_assignments existing
              ON existing.org_id = incoming.org_id AND existing.state = 'active'
            JOIN agent_group_members existing_member
              ON existing_member.org_id = existing.org_id
             AND existing_member.agent_group_id = existing.agent_group_id
            WHERE incoming.org_id = NEW.org_id AND incoming.state = 'active'
              AND incoming.agent_group_id = NEW.agent_group_id
              AND existing_member.device_id = NEW.device_id
              AND existing.agent_group_id <> incoming.agent_group_id
        ) THEN RAISE EXCEPTION 'an agent may have only one MCP profile'; END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
