-- F09: reusable access for managed agents without a second authorization model.
-- Agent groups are distinct from human user_groups. Applied template versions
-- materialize ordinary policy_rules with src_kind='agent_group'; the existing
-- compiler expands current active group members into the same IP-only artifact.

ALTER TABLE organizations
    ADD COLUMN agent_policy_templates_enabled boolean NOT NULL DEFAULT false;

-- Composite tenant keys let every F09 FK prove organization equality without
-- trusting the service to perform a preceding lookup.
ALTER TABLE devices ADD CONSTRAINT devices_id_org_key UNIQUE (id, org_id);
ALTER TABLE resources ADD CONSTRAINT resources_id_org_key UNIQUE (id, org_id);
ALTER TABLE user_groups ADD CONSTRAINT user_groups_id_org_key UNIQUE (id, org_id);
ALTER TABLE sites ADD CONSTRAINT sites_id_org_key UNIQUE (id, org_id);
ALTER TABLE k8s_services ADD CONSTRAINT k8s_services_id_org_key UNIQUE (id, org_id);

CREATE TABLE agent_groups (
    id          uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name        text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    archived_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id)
);
CREATE UNIQUE INDEX agent_groups_org_active_name_key
    ON agent_groups (org_id, lower(name)) WHERE archived_at IS NULL;
CREATE INDEX agent_groups_org_id_idx ON agent_groups (org_id, created_at, id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_groups
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE agent_group_members (
    org_id             uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    agent_group_id     uuid NOT NULL,
    device_id          uuid NOT NULL,
    created_by_user_id uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_group_id, device_id),
    FOREIGN KEY (agent_group_id, org_id)
        REFERENCES agent_groups (id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (device_id, org_id)
        REFERENCES devices (id, org_id) ON DELETE CASCADE
);
CREATE INDEX agent_group_members_org_device_idx
    ON agent_group_members (org_id, device_id, agent_group_id);

-- Membership is a managed-agent concept, not a second generic device-group
-- relation. Preserve suspended membership for resume, but refuse human,
-- revoked, deleted, or cross-tenant devices at the database boundary.
CREATE FUNCTION agent_group_member_require_live_agent() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = NEW.device_id
          AND d.org_id = NEW.org_id
          AND d.kind = 'agent'
          AND d.status IN ('active', 'suspended')
          AND d.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'agent group membership requires a live managed agent in the stated organization';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER agent_group_members_require_live_agent_before_write
    BEFORE INSERT OR UPDATE OF org_id, device_id ON agent_group_members
    FOR EACH ROW EXECUTE FUNCTION agent_group_member_require_live_agent();

CREATE TABLE agent_policy_templates (
    id          uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name        text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    archived_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id)
);
CREATE UNIQUE INDEX agent_policy_templates_org_active_name_key
    ON agent_policy_templates (org_id, lower(name)) WHERE archived_at IS NULL;
CREATE INDEX agent_policy_templates_org_id_idx
    ON agent_policy_templates (org_id, created_at, id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_policy_templates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE agent_policy_template_versions (
    id                 uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id             uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    template_id        uuid NOT NULL,
    version            integer NOT NULL CHECK (version >= 1),
    created_by_user_id uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id),
    UNIQUE (id, org_id, template_id),
    UNIQUE (template_id, version),
    FOREIGN KEY (template_id, org_id)
        REFERENCES agent_policy_templates (id, org_id) ON DELETE RESTRICT
);
CREATE INDEX agent_policy_template_versions_org_template_idx
    ON agent_policy_template_versions (org_id, template_id, version DESC);

CREATE TABLE agent_policy_template_version_items (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id              uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    template_version_id uuid NOT NULL,
    ordinal             integer NOT NULL CHECK (ordinal BETWEEN 1 AND 100),
    dst_kind            text NOT NULL CHECK (dst_kind IN ('resource', 'group', 'site', 'k8s_service')),
    dst_resource_id     uuid,
    dst_group_id        uuid,
    dst_site_id         uuid,
    dst_k8s_service_id  uuid,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id),
    UNIQUE (template_version_id, ordinal),
    FOREIGN KEY (template_version_id, org_id)
        REFERENCES agent_policy_template_versions (id, org_id) ON DELETE RESTRICT,
    FOREIGN KEY (dst_resource_id, org_id)
        REFERENCES resources (id, org_id) ON DELETE RESTRICT,
    FOREIGN KEY (dst_group_id, org_id)
        REFERENCES user_groups (id, org_id) ON DELETE RESTRICT,
    FOREIGN KEY (dst_site_id, org_id)
        REFERENCES sites (id, org_id) ON DELETE RESTRICT,
    FOREIGN KEY (dst_k8s_service_id, org_id)
        REFERENCES k8s_services (id, org_id) ON DELETE RESTRICT,
    CHECK (
        (dst_kind = 'resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
     OR (dst_kind = 'group' AND dst_group_id IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
     OR (dst_kind = 'site' AND dst_site_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_k8s_service_id IS NULL)
     OR (dst_kind = 'k8s_service' AND dst_k8s_service_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL)
    )
);
CREATE INDEX agent_policy_template_version_items_org_version_idx
    ON agent_policy_template_version_items (org_id, template_version_id, ordinal);

CREATE TABLE agent_policy_template_assignments (
    id                     uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id                 uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    agent_group_id         uuid NOT NULL,
    template_id            uuid NOT NULL,
    template_version_id    uuid NOT NULL,
    state                  text NOT NULL DEFAULT 'active'
                               CHECK (state IN ('active', 'superseded', 'removed')),
    preview_digest         text NOT NULL CHECK (preview_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key        text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    applied_by_user_id     uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    previous_assignment_id uuid,
    applied_at             timestamptz NOT NULL DEFAULT now(),
    ended_at               timestamptz,
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id),
    UNIQUE (org_id, idempotency_key),
    FOREIGN KEY (agent_group_id, org_id)
        REFERENCES agent_groups (id, org_id) ON DELETE RESTRICT,
    FOREIGN KEY (template_id, org_id)
        REFERENCES agent_policy_templates (id, org_id) ON DELETE RESTRICT,
    FOREIGN KEY (template_version_id, org_id, template_id)
        REFERENCES agent_policy_template_versions (id, org_id, template_id) ON DELETE RESTRICT,
    FOREIGN KEY (previous_assignment_id, org_id)
        REFERENCES agent_policy_template_assignments (id, org_id) ON DELETE RESTRICT,
    CHECK ((state = 'active' AND ended_at IS NULL) OR (state <> 'active' AND ended_at IS NOT NULL))
);
CREATE UNIQUE INDEX agent_policy_template_assignments_one_active
    ON agent_policy_template_assignments (org_id, agent_group_id, template_id)
    WHERE state = 'active';
CREATE INDEX agent_policy_template_assignments_org_group_idx
    ON agent_policy_template_assignments (org_id, agent_group_id, applied_at DESC);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON agent_policy_template_assignments
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Actor IDs are immutable provenance. Validate current tenant membership at
-- write time without cascading historical rows when membership later ends.
CREATE FUNCTION agent_policy_template_actor_require_membership() RETURNS trigger AS $$
DECLARE
    actor uuid;
BEGIN
    IF TG_TABLE_NAME = 'agent_group_members' THEN
        actor := NEW.created_by_user_id;
    ELSIF TG_TABLE_NAME = 'agent_policy_template_versions' THEN
        actor := NEW.created_by_user_id;
    ELSE
        actor := NEW.applied_by_user_id;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM memberships m
        JOIN users u ON u.id = m.user_id
        WHERE m.org_id = NEW.org_id
          AND m.user_id = actor
          AND u.status = 'active'
          AND u.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'agent policy template actor must be a current active member of the stated organization';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER agent_group_members_actor_before_write
    BEFORE INSERT OR UPDATE OF org_id, created_by_user_id ON agent_group_members
    FOR EACH ROW EXECUTE FUNCTION agent_policy_template_actor_require_membership();
CREATE TRIGGER agent_policy_template_versions_actor_before_write
    BEFORE INSERT OR UPDATE OF org_id, created_by_user_id ON agent_policy_template_versions
    FOR EACH ROW EXECUTE FUNCTION agent_policy_template_actor_require_membership();
CREATE TRIGGER agent_policy_template_assignments_actor_before_write
    BEFORE INSERT OR UPDATE OF org_id, applied_by_user_id ON agent_policy_template_assignments
    FOR EACH ROW EXECUTE FUNCTION agent_policy_template_actor_require_membership();

-- Extend the ordinary policy source union with agent_group. The source FK is
-- restrictive so group deletion cannot silently withdraw live access.
ALTER TABLE policy_rules ADD COLUMN src_agent_group_id uuid;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_id_org_key UNIQUE (id, org_id);
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_agent_group_fk
    FOREIGN KEY (src_agent_group_id, org_id)
    REFERENCES agent_groups (id, org_id) ON DELETE RESTRICT;

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_kind_check
    CHECK (src_kind IN ('group', 'user', 'site', 'cidr', 'agent', 'agent_group'));

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_src_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_src_check CHECK (
    (src_kind = 'group' AND src_group_id IS NOT NULL AND src_user_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL AND src_device_id IS NULL AND src_agent_group_id IS NULL)
 OR (src_kind = 'user' AND src_user_id IS NOT NULL AND src_group_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL AND src_device_id IS NULL AND src_agent_group_id IS NULL)
 OR (src_kind = 'site' AND src_site_id IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_cidr IS NULL AND src_device_id IS NULL AND src_agent_group_id IS NULL)
 OR (src_kind = 'cidr' AND src_cidr IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_site_id IS NULL AND src_device_id IS NULL AND src_agent_group_id IS NULL)
 OR (src_kind = 'agent' AND src_device_id IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL AND src_agent_group_id IS NULL)
 OR (src_kind = 'agent_group' AND src_agent_group_id IS NOT NULL AND src_group_id IS NULL AND src_user_id IS NULL AND src_site_id IS NULL AND src_cidr IS NULL AND src_device_id IS NULL)
);
CREATE INDEX policy_rules_src_agent_group_idx
    ON policy_rules (org_id, src_agent_group_id)
    WHERE src_kind = 'agent_group';
CREATE UNIQUE INDEX policy_rules_agent_group_resource_uniq
    ON policy_rules (org_id, src_agent_group_id, dst_resource_id)
    WHERE src_kind = 'agent_group' AND dst_kind = 'resource';
CREATE UNIQUE INDEX policy_rules_agent_group_group_uniq
    ON policy_rules (org_id, src_agent_group_id, dst_group_id)
    WHERE src_kind = 'agent_group' AND dst_kind = 'group';
CREATE UNIQUE INDEX policy_rules_agent_group_site_uniq
    ON policy_rules (org_id, src_agent_group_id, dst_site_id)
    WHERE src_kind = 'agent_group' AND dst_kind = 'site';
CREATE UNIQUE INDEX policy_rules_agent_group_k8s_service_uniq
    ON policy_rules (org_id, src_agent_group_id, dst_k8s_service_id)
    WHERE src_kind = 'agent_group' AND dst_kind = 'k8s_service';
CREATE UNIQUE INDEX policy_rules_agent_group_k8s_cluster_scope_uniq
    ON policy_rules (org_id, src_agent_group_id, dst_k8s_cluster_id)
    WHERE src_kind = 'agent_group' AND dst_kind = 'k8s_cluster_scope';

CREATE TABLE agent_policy_template_rule_bindings (
    org_id                   uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    assignment_id           uuid NOT NULL,
    template_version_item_id uuid NOT NULL,
    policy_rule_id           uuid NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (assignment_id, template_version_item_id),
    FOREIGN KEY (assignment_id, org_id)
        REFERENCES agent_policy_template_assignments (id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (template_version_item_id, org_id)
        REFERENCES agent_policy_template_version_items (id, org_id) ON DELETE RESTRICT,
    FOREIGN KEY (policy_rule_id, org_id)
        REFERENCES policy_rules (id, org_id) ON DELETE RESTRICT
);
CREATE INDEX agent_policy_template_rule_bindings_org_rule_idx
    ON agent_policy_template_rule_bindings (org_id, policy_rule_id);
