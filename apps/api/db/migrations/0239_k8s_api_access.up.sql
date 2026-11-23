-- K8N-3 stage 1: the cluster's Kubernetes API as a named destination (docs/K8N-3-kubectl-access.md).
--
-- A registered cluster gains "API access", off by default. Turning it on allocates ONE address from the
-- cluster's range and maps it to the Service default/kubernetes on TCP 443. A rule with the new destination
-- kind 'k8s_api' grants a person or a group TCP 443 to that address. Tunnex carries the connection and
-- nothing else: no cluster credential is issued, stored or seen.
--
-- The endpoint lives in its own table, not in k8s_services, so it can never be a cluster-scope member, an
-- agent-access destination or an agent-template destination: those all key on k8s_services rows.

CREATE TABLE k8s_api_endpoints (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    cluster_id         uuid        NOT NULL REFERENCES k8s_clusters (id) ON DELETE CASCADE,
    -- Off keeps the row (and the rules that point at it, which then allow nothing) and gives the address back.
    enabled            boolean     NOT NULL DEFAULT false,
    vip                inet,
    enabled_at         timestamptz,
    enabled_by_user_id uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cluster_id),
    CONSTRAINT k8s_api_endpoints_enabled_has_vip CHECK (enabled = (vip IS NOT NULL))
);

CREATE INDEX k8s_api_endpoints_org_idx ON k8s_api_endpoints (org_id) WHERE enabled;

CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_api_endpoints
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The address must be the cluster's own, inside its range, and neither the reserved DNS address nor the
-- address of an exposed Service. The control plane allocates around all three; this is the backstop.
CREATE FUNCTION k8s_api_endpoints_check_vip() RETURNS trigger AS $$
DECLARE
    cluster_org   uuid;
    cluster_range cidr;
    cluster_dns   inet;
BEGIN
    SELECT org_id, vip_range, dns_vip INTO cluster_org, cluster_range, cluster_dns
    FROM k8s_clusters WHERE id = NEW.cluster_id;
    IF cluster_org IS DISTINCT FROM NEW.org_id THEN
        RAISE EXCEPTION 'k8s_api_endpoint_org_mismatch';
    END IF;
    IF NEW.vip IS NULL THEN
        RETURN NEW;
    END IF;
    IF masklen(NEW.vip) <> 32 OR NOT (NEW.vip <<= cluster_range) THEN
        RAISE EXCEPTION 'k8s_api_endpoint_vip_outside_cluster_range';
    END IF;
    IF cluster_dns IS NOT NULL AND host(cluster_dns) = host(NEW.vip) THEN
        RAISE EXCEPTION 'k8s_api_endpoint_vip_is_dns_vip';
    END IF;
    IF EXISTS (SELECT 1 FROM k8s_service_identities i
               WHERE i.cluster_id = NEW.cluster_id AND i.deleted_at IS NULL AND host(i.vip) = host(NEW.vip)) THEN
        RAISE EXCEPTION 'k8s_api_endpoint_vip_in_use' USING ERRCODE = 'exclusion_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_api_endpoints_vip_before_write
    BEFORE INSERT OR UPDATE OF org_id, cluster_id, vip ON k8s_api_endpoints
    FOR EACH ROW EXECUTE FUNCTION k8s_api_endpoints_check_vip();

-- The mirror: an exposed Service is never handed the API's address.
CREATE FUNCTION k8s_service_identities_refuse_api_vip() RETURNS trigger AS $$
BEGIN
    IF NEW.deleted_at IS NULL AND EXISTS (
        SELECT 1 FROM k8s_api_endpoints e
        WHERE e.cluster_id = NEW.cluster_id AND e.vip IS NOT NULL AND host(e.vip) = host(NEW.vip)
    ) THEN
        RAISE EXCEPTION 'k8s_service_vip_reserved_for_api_access' USING ERRCODE = 'exclusion_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER k8s_service_identities_api_vip_before_write
    BEFORE INSERT OR UPDATE OF vip, deleted_at ON k8s_service_identities
    FOR EACH ROW EXECUTE FUNCTION k8s_service_identities_refuse_api_vip();

-- The rule column. A hard delete of the endpoint (its cluster is deregistered) removes dependent rules,
-- as for an exposed Service (0049). Turning API access off keeps the row, so the rules stay and compile
-- to nothing.
ALTER TABLE policy_rules
    ADD COLUMN dst_k8s_api_endpoint_id uuid REFERENCES k8s_api_endpoints (id) ON DELETE CASCADE;

-- 0123 authored the current shape of both checks. Re-expand it with the new arm; no existing arm changes
-- except to state that the new column is empty.
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_dst_kind_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_dst_kind_check
    CHECK (dst_kind IN ('resource','group','site','k8s_service','fqdn_resource','k8s_cluster_scope','k8s_api'));
ALTER TABLE policy_rules DROP CONSTRAINT policy_rules_check;
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_check CHECK (
    (dst_kind='resource' AND dst_resource_id IS NOT NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL AND dst_k8s_api_endpoint_id IS NULL)
 OR (dst_kind='group' AND dst_group_id IS NOT NULL AND dst_resource_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL AND dst_k8s_api_endpoint_id IS NULL)
 OR (dst_kind='site' AND dst_site_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL AND dst_k8s_api_endpoint_id IS NULL)
 OR (dst_kind='k8s_service' AND dst_k8s_service_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL AND dst_k8s_api_endpoint_id IS NULL)
 OR (dst_kind='fqdn_resource' AND dst_fqdn_resource_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_k8s_cluster_id IS NULL AND dst_k8s_api_endpoint_id IS NULL)
 OR (dst_kind='k8s_cluster_scope' AND dst_k8s_cluster_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_api_endpoint_id IS NULL)
 OR (dst_kind='k8s_api' AND dst_k8s_api_endpoint_id IS NOT NULL AND dst_resource_id IS NULL AND dst_group_id IS NULL AND dst_site_id IS NULL AND dst_k8s_service_id IS NULL AND dst_fqdn_resource_id IS NULL AND dst_k8s_cluster_id IS NULL)
);

-- Founder ruling 2026-11-23: people and groups only. A site, an address range, an agent or an agent group
-- can never be the source of an API rule, whatever wrote the row.
ALTER TABLE policy_rules ADD CONSTRAINT policy_rules_k8s_api_people_only
    CHECK (dst_kind <> 'k8s_api' OR src_kind IN ('group', 'user'));

-- One rule per (person or group, cluster API), as for every other destination kind.
CREATE UNIQUE INDEX policy_rules_group_k8s_api_uniq ON policy_rules (org_id, src_group_id, dst_k8s_api_endpoint_id)
    WHERE src_kind = 'group' AND dst_kind = 'k8s_api';
CREATE UNIQUE INDEX policy_rules_user_k8s_api_uniq ON policy_rules (org_id, src_user_id, dst_k8s_api_endpoint_id)
    WHERE src_kind = 'user' AND dst_kind = 'k8s_api';
CREATE INDEX policy_rules_dst_k8s_api_endpoint_idx ON policy_rules (dst_k8s_api_endpoint_id)
    WHERE dst_k8s_api_endpoint_id IS NOT NULL;
