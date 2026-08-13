-- 0018 zero trust policy model (S7.1) — user-groups, resources, allow-rules, org mode.
--
-- ENTERPRISE feature (edition-gated at the API layer). This migration is the MODEL
-- only; there is NO data-plane change here — S7.2 compiles + enforces. The model is
-- ALLOW-ONLY with implicit DEFAULT-DENY: a rule is a grant, and anything not granted
-- is denied (structurally, by S7.2's nftables policy-drop base — never a stored deny
-- row, so there is no rule ordering/precedence to reason about).
--
-- Policy objects are HARD-deleted (no deleted_at): FK ON DELETE CASCADE cleans up
-- dependent rules, and audit_logs record the change. So none of these tables carry
-- the soft-delete resurrection concern the query-lint guards.

-- user_groups: the SUBJECT of every policy rule. Named `user_groups` (not `groups`)
-- because GROUP is a SQL reserved word. A group holds org members (group_members).
CREATE TABLE user_groups (
    id          uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX user_groups_org_name_key ON user_groups (org_id, lower(name));
CREATE INDEX user_groups_org_id_idx ON user_groups (org_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON user_groups
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- group_members: user<->group. org_id is denormalized (NOT NULL) so every query
-- scopes by org_id directly (tenant-lint) without a join. A group only meaningfully
-- contains users who are org members; that invariant is enforced at the service layer.
CREATE TABLE group_members (
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    group_id   uuid NOT NULL REFERENCES user_groups (id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id),
    -- A group member MUST be a current org member: this composite FK both refuses
    -- adding a non-member AND — the load-bearing part — CASCADES on membership
    -- removal, so revoking a member instantly drops their group grants. Without it,
    -- RemoveMember deletes only the memberships row and a removed user would retain
    -- scoped network access under enforcing mode (their device still reachable).
    FOREIGN KEY (org_id, user_id) REFERENCES memberships (org_id, user_id) ON DELETE CASCADE
);
CREATE INDEX group_members_org_id_idx ON group_members (org_id);
CREATE INDEX group_members_user_idx ON group_members (org_id, user_id);

-- resources: a named STATIC destination — a CIDR + optional L4 (protocol + port
-- range). protocol 'any' ignores ports (port_low/high NULL). '0.0.0.0/0' names the
-- internet (an egress grant). cidr stored as text, validated app-side (ParsePrefix),
-- consistent with devices.assigned_ip.
CREATE TABLE resources (
    id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name       text NOT NULL,
    cidr       text NOT NULL,
    protocol   text NOT NULL DEFAULT 'any' CHECK (protocol IN ('any', 'tcp', 'udp')),
    port_low   integer CHECK (port_low  IS NULL OR (port_low  BETWEEN 1 AND 65535)),
    port_high  integer CHECK (port_high IS NULL OR (port_high BETWEEN 1 AND 65535)),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    -- ports only make sense for tcp/udp, and low<=high; 'any' carries no ports.
    CHECK ((protocol = 'any' AND port_low IS NULL AND port_high IS NULL)
        OR (protocol IN ('tcp', 'udp'))),
    CHECK (port_low IS NULL OR port_high IS NULL OR port_low <= port_high)
);
CREATE UNIQUE INDEX resources_org_name_key ON resources (org_id, lower(name));
CREATE INDEX resources_org_id_idx ON resources (org_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON resources
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- policy_rules: an ALLOW grant — members of src_group may reach dst. dst is EITHER a
-- resource (static cidr:ports) OR a group (dynamic: that group's members' device
-- /32s — device-to-device). Exactly one dst_* column is set, matching dst_kind.
CREATE TABLE policy_rules (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    src_group_id    uuid NOT NULL REFERENCES user_groups (id) ON DELETE CASCADE,
    dst_kind        text NOT NULL CHECK (dst_kind IN ('resource', 'group')),
    dst_resource_id uuid REFERENCES resources (id) ON DELETE CASCADE,
    dst_group_id    uuid REFERENCES user_groups (id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK ((dst_kind = 'resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL)
        OR (dst_kind = 'group'    AND dst_group_id    IS NOT NULL AND dst_resource_id IS NULL))
);
CREATE INDEX policy_rules_org_id_idx ON policy_rules (org_id);
-- De-dup identical grants (partial per dst kind, since one dst_* is always NULL).
CREATE UNIQUE INDEX policy_rules_resource_uniq ON policy_rules (org_id, src_group_id, dst_resource_id)
    WHERE dst_kind = 'resource';
CREATE UNIQUE INDEX policy_rules_group_uniq ON policy_rules (org_id, src_group_id, dst_group_id)
    WHERE dst_kind = 'group';

-- Org-level enforcement mode. DEFAULT 'off' = today's blanket mesh (NO silent break
-- on upgrade); 'enforcing' = default-deny + compiled allows. Mode is a COMPILER INPUT
-- (S7.2), not enforcement-layer special-casing. Flipping it is an audited admin action.
ALTER TABLE organizations ADD COLUMN zero_trust_mode text NOT NULL DEFAULT 'off'
    CHECK (zero_trust_mode IN ('off', 'enforcing'));
