-- S21 Lane 1: make an FQDN resource a first-class policy destination.  The
-- old side table was an expand-only scaffold: it did not make the rule itself
-- intelligible to the API, compiler, or database constraints.

ALTER TABLE policy_rules
    ADD COLUMN dst_fqdn_resource_id uuid NULL;

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource', 'group', 'site', 'k8s_service', 'fqdn_resource'));

ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind = 'resource'      AND dst_resource_id      IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL)
 OR (dst_kind = 'group'         AND dst_group_id         IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL)
 OR (dst_kind = 'site'          AND dst_site_id          IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL)
 OR (dst_kind = 'k8s_service'   AND dst_k8s_service_id   IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_fqdn_resource_id IS NULL)
 OR (dst_kind = 'fqdn_resource' AND dst_fqdn_resource_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL)
);

-- A legacy scaffold reference means exactly the new destination.  Preserve it
-- during the contraction rather than losing an operator-authored reference.
UPDATE policy_rules r
SET dst_kind = 'fqdn_resource',
    dst_resource_id = NULL,
    dst_group_id = NULL,
    dst_site_id = NULL,
    dst_k8s_service_id = NULL,
    dst_fqdn_resource_id = x.resource_id
FROM fqdn_resource_rule_references x
WHERE x.policy_rule_id = r.id AND x.org_id = r.org_id;

-- The composite FK is the same-org reference lifecycle.  RESTRICT makes an
-- attempted resource deletion truthful: the service can project the blocking
-- rule identities rather than silently cascading grants away.
ALTER TABLE policy_rules
    ADD CONSTRAINT policy_rules_dst_fqdn_resource_org_fkey
    FOREIGN KEY (dst_fqdn_resource_id, org_id)
    REFERENCES fqdn_resources (id, org_id) ON DELETE RESTRICT;
CREATE INDEX policy_rules_org_dst_fqdn_resource_idx
    ON policy_rules (org_id, dst_fqdn_resource_id)
    WHERE dst_kind = 'fqdn_resource';

CREATE UNIQUE INDEX policy_rules_group_fqdn_resource_uniq
    ON policy_rules (org_id, src_group_id, dst_fqdn_resource_id)
    WHERE src_kind = 'group' AND dst_kind = 'fqdn_resource';
CREATE UNIQUE INDEX policy_rules_user_fqdn_resource_uniq
    ON policy_rules (org_id, src_user_id, dst_fqdn_resource_id)
    WHERE src_kind = 'user' AND dst_kind = 'fqdn_resource';
CREATE UNIQUE INDEX policy_rules_site_fqdn_resource_uniq
    ON policy_rules (org_id, src_site_id, dst_fqdn_resource_id)
    WHERE src_kind = 'site' AND dst_kind = 'fqdn_resource';
CREATE UNIQUE INDEX policy_rules_cidr_fqdn_resource_uniq
    ON policy_rules (org_id, src_cidr, dst_fqdn_resource_id)
    WHERE src_kind = 'cidr' AND dst_kind = 'fqdn_resource';
CREATE UNIQUE INDEX policy_rules_agent_fqdn_resource_uniq
    ON policy_rules (org_id, src_device_id, dst_fqdn_resource_id)
    WHERE src_kind = 'agent' AND dst_kind = 'fqdn_resource';
CREATE UNIQUE INDEX policy_rules_agent_group_fqdn_resource_uniq
    ON policy_rules (org_id, src_agent_group_id, dst_fqdn_resource_id)
    WHERE src_kind = 'agent_group' AND dst_kind = 'fqdn_resource';

-- Keep the expand-era table for one rolling-release compatibility window: an
-- older control plane can still read its known relation while this version
-- treats policy_rules.dst_fqdn_resource_id as authoritative. The mirror is
-- maintained transactionally and is deliberately not the source of truth.
CREATE FUNCTION fqdn_policy_rule_reference_mirror() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM fqdn_resource_rule_references WHERE policy_rule_id = OLD.id;
        RETURN OLD;
    END IF;
    IF NEW.dst_kind = 'fqdn_resource' THEN
        INSERT INTO fqdn_resource_rule_references (policy_rule_id, org_id, resource_id)
        VALUES (NEW.id, NEW.org_id, NEW.dst_fqdn_resource_id)
        ON CONFLICT (policy_rule_id) DO UPDATE SET org_id=EXCLUDED.org_id, resource_id=EXCLUDED.resource_id;
    ELSE
        DELETE FROM fqdn_resource_rule_references WHERE policy_rule_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fqdn_policy_rule_reference_mirror_after_write
    AFTER INSERT OR UPDATE OF dst_kind, dst_fqdn_resource_id OR DELETE ON policy_rules
    FOR EACH ROW EXECUTE FUNCTION fqdn_policy_rule_reference_mirror();

-- TCP/UDP means either no port restriction or one complete closed range.  A
-- half-range is ambiguous to every compiler and is rejected at the DB boundary
-- even when a non-HTTP writer bypasses API validation.
ALTER TABLE resources DROP CONSTRAINT resources_check;
ALTER TABLE resources DROP CONSTRAINT resources_check1;
ALTER TABLE resources ADD CONSTRAINT resources_ports_complete_check CHECK (
    (protocol = 'any' AND port_low IS NULL AND port_high IS NULL)
 OR (protocol IN ('tcp', 'udp') AND ((port_low IS NULL AND port_high IS NULL) OR (port_low IS NOT NULL AND port_high IS NOT NULL AND port_low <= port_high)))
);
ALTER TABLE fqdn_resources DROP CONSTRAINT fqdn_resources_check;
ALTER TABLE fqdn_resources ADD CONSTRAINT fqdn_resources_ports_complete_check CHECK (
    (protocol = 'any' AND port_low IS NULL AND port_high IS NULL)
 OR (protocol IN ('tcp', 'udp') AND ((port_low IS NULL AND port_high IS NULL) OR (port_low IS NOT NULL AND port_high IS NOT NULL AND port_low <= port_high)))
);

-- An answer generation is a published identity, not a mutable cache row.
-- Pending may be assembled; thereafter only the explicitly listed terminal
-- state transition can occur and identity/answer metadata cannot be rewritten.
CREATE FUNCTION fqdn_generation_published_immutable() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.state <> 'pending' THEN
        RAISE EXCEPTION 'published FQDN answer generations cannot be deleted';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.state <> 'pending' THEN
        IF OLD.state <> 'active' OR NEW.state NOT IN ('retired', 'withdrawn')
           OR NEW.id IS DISTINCT FROM OLD.id OR NEW.org_id IS DISTINCT FROM OLD.org_id
           OR NEW.resource_id IS DISTINCT FROM OLD.resource_id OR NEW.generation IS DISTINCT FROM OLD.generation
           OR NEW.resolver_node_id IS DISTINCT FROM OLD.resolver_node_id OR NEW.resolver_site_id IS DISTINCT FROM OLD.resolver_site_id
           OR NEW.effective_ttl IS DISTINCT FROM OLD.effective_ttl OR NEW.resolved_at IS DISTINCT FROM OLD.resolved_at
           OR NEW.last_good_at IS DISTINCT FROM OLD.last_good_at OR NEW.activated_at IS DISTINCT FROM OLD.activated_at
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'published FQDN answer generations are immutable except active terminal transition';
        END IF;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fqdn_generation_published_immutable_before_update
    BEFORE UPDATE ON fqdn_resource_answer_generations
    FOR EACH ROW EXECUTE FUNCTION fqdn_generation_published_immutable();
CREATE TRIGGER fqdn_generation_published_immutable_before_delete
    BEFORE DELETE ON fqdn_resource_answer_generations
    FOR EACH ROW EXECUTE FUNCTION fqdn_generation_published_immutable();
