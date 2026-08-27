-- S21 D2/D6/D7/D9 reconciliation.  0110 deliberately stored a node-only
-- resolver selector as an additive scaffold.  A node is not a split-horizon
-- authority: the authority is the tenant-scoped (site, gateway) pair.
-- Existing CIDR resources and policy_rules are intentionally untouched.

ALTER TABLE organizations
    ADD COLUMN fqdn_resources_enabled boolean NOT NULL DEFAULT false;

ALTER TABLE fqdn_resources
    ADD COLUMN resolver_site_id uuid NULL REFERENCES sites(id) ON DELETE RESTRICT;

ALTER TABLE fqdn_resource_answer_generations
    ADD COLUMN resolver_site_id uuid NULL REFERENCES sites(id) ON DELETE RESTRICT;

-- `resolver_node_id` is retained as the physical gateway identity for a
-- compatible expand/contract rollout.  The pair is either wholly absent (a
-- draft) or wholly present; a trigger below proves the gateway is in that
-- site and tenant rather than trusting a client supplied relationship.
ALTER TABLE fqdn_resources
    ADD CONSTRAINT fqdn_resources_resolver_context_pair
    CHECK ((resolver_site_id IS NULL) = (resolver_node_id IS NULL));
ALTER TABLE fqdn_resource_answer_generations
    ADD CONSTRAINT fqdn_generations_resolver_context_pair
    CHECK (resolver_site_id IS NOT NULL);

CREATE INDEX fqdn_resources_org_resolver_site_idx
    ON fqdn_resources (org_id, resolver_site_id)
    WHERE resolver_site_id IS NOT NULL;

CREATE FUNCTION fqdn_resolver_context_is_selected() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM nodes n
        WHERE n.id = NEW.resolver_node_id
          AND n.org_id = NEW.org_id
          AND n.site_id = NEW.resolver_site_id
          AND n.status = 'active'
    ) THEN
        RAISE EXCEPTION 'FQDN resolver context must be an active gateway bound to the selected site in this organization';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER fqdn_resource_resolver_context_before_write
    BEFORE INSERT OR UPDATE OF org_id, resolver_site_id, resolver_node_id ON fqdn_resources
    FOR EACH ROW WHEN (NEW.resolver_site_id IS NOT NULL)
    EXECUTE FUNCTION fqdn_resolver_context_is_selected();
CREATE TRIGGER fqdn_generation_resolver_context_before_write
    BEFORE INSERT OR UPDATE OF org_id, resolver_site_id, resolver_node_id ON fqdn_resource_answer_generations
    FOR EACH ROW EXECUTE FUNCTION fqdn_resolver_context_is_selected();

-- A gateway cannot silently be re-homed away from an FQDN authority.  The
-- resource must be deliberately edited back to draft or another selected pair.
CREATE FUNCTION fqdn_resolver_gateway_rebind_restricted() RETURNS trigger AS $$
BEGIN
    IF OLD.site_id IS DISTINCT FROM NEW.site_id AND EXISTS (
        SELECT 1 FROM fqdn_resources r
        WHERE r.resolver_node_id = OLD.id AND r.resolver_site_id = OLD.site_id
    ) THEN
        RAISE EXCEPTION 'cannot rebind gateway while it is selected by an FQDN resource';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER fqdn_resolver_gateway_rebind_before_write
    BEFORE UPDATE OF site_id ON nodes
    FOR EACH ROW EXECUTE FUNCTION fqdn_resolver_gateway_rebind_restricted();

-- Rules name an FQDN resource through a separate reference, never through the
-- legacy CIDR resource column.  Deletion is RESTRICT so the service can return
-- exact impact and require an explicit recovery workflow instead of cascading.
CREATE TABLE fqdn_resource_rule_references (
    policy_rule_id  uuid PRIMARY KEY REFERENCES policy_rules(id) ON DELETE CASCADE,
    org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource_id     uuid NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (resource_id, org_id)
        REFERENCES fqdn_resources(id, org_id) ON DELETE RESTRICT
);
CREATE INDEX fqdn_resource_rule_references_impact_idx
    ON fqdn_resource_rule_references (org_id, resource_id);

