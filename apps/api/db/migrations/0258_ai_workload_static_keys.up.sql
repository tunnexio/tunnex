-- AI-KEYS-1: static API keys for workloads, the internal AI endpoint served by
-- a gateway, and its per-organization private CA. Additive only.

ALTER TABLE organizations ADD COLUMN ai_public_static_keys_allowed boolean NOT NULL DEFAULT false;

CREATE TABLE ai_workload_static_keys (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100 AND name !~ '[\r\n]'),
    secret_hash bytea NOT NULL UNIQUE CHECK (octet_length(secret_hash) = 32),
    hint text NOT NULL CHECK (char_length(hint) = 4),
    scope text NOT NULL CHECK (scope IN ('internal','public')),
    source_cidrs cidr[] NOT NULL DEFAULT '{}' CHECK (cardinality(source_cidrs) <= 32),
    daily_usd_threshold double precision CHECK (daily_usd_threshold > 0 AND daily_usd_threshold <= 100000),
    rate_limit_per_minute integer CHECK (rate_limit_per_minute BETWEEN 1 AND 60000),
    workload_epoch bigint NOT NULL CHECK (workload_epoch > 0),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_by uuid,
    rotated_from_id uuid,
    native_key_id text NOT NULL DEFAULT '',
    sealed_key text NOT NULL DEFAULT '',
    binding_revision bigint NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','error','revoked')),
    engine_disabled_at timestamptz,
    last_used_at timestamptz,
    last_used_ingress text CHECK (last_used_ingress IN ('internal','public')),
    last_used_source inet,
    last_used_node_id uuid,
    last_refused_at timestamptz,
    last_refused_reason text CHECK (char_length(last_refused_reason) <= 64),
    last_refused_ingress text CHECK (last_refused_ingress IN ('internal','public')),
    last_refused_source inet,
    last_refused_node_id uuid,
    last_refusal_audit_at timestamptz,
    expiry_alert_14_at timestamptz,
    expiry_alert_3_at timestamptz,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, workload_id, id),
    FOREIGN KEY (org_id, workload_id) REFERENCES ai_workloads(org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, workload_id, rotated_from_id) REFERENCES ai_workload_static_keys(org_id, workload_id, id),
    CHECK (expires_at <= created_at + interval '90 days'),
    CHECK (rotated_from_id IS NULL OR rotated_from_id <> id)
);
CREATE INDEX ai_workload_static_keys_active ON ai_workload_static_keys (org_id, workload_id) WHERE revoked_at IS NULL;
CREATE INDEX ai_workload_static_keys_expiry ON ai_workload_static_keys (expires_at);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON ai_workload_static_keys
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE ai_internal_endpoints (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    node_id uuid NOT NULL UNIQUE REFERENCES nodes(id) ON DELETE CASCADE,
    enabled boolean NOT NULL,
    listen_addresses inet[] NOT NULL CHECK (cardinality(listen_addresses) BETWEEN 1 AND 2),
    port integer NOT NULL DEFAULT 9443 CHECK (port BETWEEN 1024 AND 65535 AND port NOT IN (8083, 8084)),
    dns_name text CHECK (dns_name = lower(dns_name) AND char_length(dns_name) BETWEEN 1 AND 253),
    source_cidrs cidr[] NOT NULL CHECK (cardinality(source_cidrs) BETWEEN 1 AND 32),
    tls_mode text NOT NULL DEFAULT 'tunnex_ca' CHECK (tls_mode IN ('tunnex_ca','custom')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by uuid,
    updated_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, id)
);
CREATE INDEX ai_internal_endpoints_org ON ai_internal_endpoints (org_id, node_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON ai_internal_endpoints
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The endpoint row must name a gateway of its own organization.
CREATE FUNCTION ai_internal_endpoint_same_org() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM nodes WHERE id = NEW.node_id AND org_id = NEW.org_id) THEN
        RAISE EXCEPTION 'internal AI endpoint gateway belongs to another organization';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER ai_internal_endpoint_same_org BEFORE INSERT OR UPDATE ON ai_internal_endpoints
    FOR EACH ROW EXECUTE FUNCTION ai_internal_endpoint_same_org();

CREATE TABLE ai_internal_cas (
    org_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    certificate_pem text NOT NULL,
    sealed_key text NOT NULL,
    not_after timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON ai_internal_cas
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Static key expiry reminders are an alert event.
ALTER TABLE alert_subscriptions DROP CONSTRAINT alert_subscriptions_event_key_check;
ALTER TABLE alert_subscriptions ADD CONSTRAINT alert_subscriptions_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending','ai_workload.static_key_expiring'));
ALTER TABLE alert_deliveries DROP CONSTRAINT alert_deliveries_event_key_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending','ai_workload.static_key_expiring'));
ALTER TABLE alert_delivery_cooldowns DROP CONSTRAINT alert_delivery_cooldowns_event_key_check;
ALTER TABLE alert_delivery_cooldowns ADD CONSTRAINT alert_delivery_cooldowns_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending','ai_workload.static_key_expiring'));
ALTER TABLE alert_occurrences DROP CONSTRAINT alert_occurrences_event_key_check;
ALTER TABLE alert_occurrences ADD CONSTRAINT alert_occurrences_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending','ai_workload.static_key_expiring'));
