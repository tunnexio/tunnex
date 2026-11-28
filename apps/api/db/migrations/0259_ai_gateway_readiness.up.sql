-- AI-READY-1: operator model prices, unknown-price policy, budget alert marks,
-- the per-request AI log, and two AI alert event keys.
-- Requires 0257 (AI-CATALOG-1, PR #146). 0258 is reserved by the static-keys
-- branch, which must merge first; its alert key ai_workload.static_key_expiring
-- is kept in the constraint lists below so merging both never drops it.

-- Per-organization model prices. The control plane is the source of truth;
-- the engine receives provider-key-scoped pricing overrides. applied_revision
-- moves only after the engine read-back confirms them, and admission uses a
-- price only when applied_revision = revision. A removed price is a tombstone
-- so the revision only increases and a stale editor always conflicts.
CREATE TABLE ai_model_price_overrides (
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    model text NOT NULL CHECK (model ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}/[A-Za-z0-9][A-Za-z0-9_./:-]{0,254}$'),
    input_cost_per_token double precision CHECK (input_cost_per_token >= 0 AND input_cost_per_token <= 0.01),
    output_cost_per_token double precision CHECK (output_cost_per_token >= 0 AND output_cost_per_token <= 0.01),
    removed boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    applied_revision bigint NOT NULL DEFAULT 0 CHECK (applied_revision >= 0 AND applied_revision <= revision),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','error')),
    updated_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, model),
    CHECK (removed OR input_cost_per_token IS NOT NULL)
);
CREATE INDEX ai_model_price_overrides_pending ON ai_model_price_overrides (org_id) WHERE applied_revision < revision;
COMMENT ON TABLE ai_model_price_overrides IS 'Operator USD per-token prices per organization and canonical model. Pushed to the engine as provider-key-scoped pricing overrides; never global.';
CREATE TRIGGER set_updated_at BEFORE UPDATE ON ai_model_price_overrides
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Organization AI cost settings. A missing row is the default: block unknown
-- prices for limited subjects, keep the request log for 30 days.
CREATE TABLE ai_gateway_cost_settings (
    org_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    unknown_price_policy text NOT NULL DEFAULT 'block' CHECK (unknown_price_policy IN ('block','allow_and_alert')),
    request_log_retention_days integer NOT NULL DEFAULT 30 CHECK (request_log_retention_days BETWEEN 1 AND 365),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by uuid,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON ai_gateway_cost_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Once-per-UTC-day alert marks (budget thresholds, unknown prices). Only the
-- insert that creates a mark publishes its alert.
CREATE TABLE ai_gateway_alert_marks (
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    day date NOT NULL,
    mark_key text NOT NULL CHECK (char_length(mark_key) BETWEEN 1 AND 600),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, day, mark_key)
);
CREATE INDEX ai_gateway_alert_marks_day ON ai_gateway_alert_marks (day);

-- Per-request AI log. Metadata only: never prompts, completions, bodies,
-- headers, keys or tokens. id is also the engine log entry ID, which the
-- enricher reads for tokens and cost.
CREATE TABLE ai_request_log (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    occurred_at timestamptz NOT NULL,
    subject_kind text NOT NULL CHECK (subject_kind IN ('user','agent','workload')),
    subject_id uuid,
    group_kind text CHECK (group_kind IN ('user_group','agent_group')),
    group_id uuid,
    instance_id uuid,
    model text NOT NULL CHECK (char_length(model) BETWEEN 1 AND 512),
    mode text NOT NULL CHECK (char_length(mode) BETWEEN 1 AND 32),
    ingress text NOT NULL CHECK (ingress IN ('public','vpn','agent','workload')),
    status_code smallint NOT NULL CHECK (status_code BETWEEN 100 AND 599),
    outcome text NOT NULL CHECK (outcome IN ('ok','refused','error')),
    refusal_code text CHECK (refusal_code ~ '^[a-z0-9_]{1,64}$'),
    latency_ms integer NOT NULL CHECK (latency_ms >= 0),
    prompt_tokens bigint CHECK (prompt_tokens >= 0),
    completion_tokens bigint CHECK (completion_tokens >= 0),
    cost_usd double precision CHECK (cost_usd >= 0),
    cost_state text NOT NULL CHECK (cost_state IN ('pending','costed','uncosted','unavailable','not_applicable')),
    request_id text CHECK (char_length(request_id) <= 128),
    CHECK ((group_kind IS NULL) = (group_id IS NULL)),
    CHECK (cost_state = 'costed' OR cost_usd IS NULL)
);
CREATE INDEX ai_request_log_org_time ON ai_request_log (org_id, occurred_at DESC, id DESC);
CREATE INDEX ai_request_log_org_subject ON ai_request_log (org_id, subject_id, occurred_at DESC);
CREATE INDEX ai_request_log_org_model ON ai_request_log (org_id, model, occurred_at DESC);
CREATE INDEX ai_request_log_pending ON ai_request_log (occurred_at) WHERE cost_state = 'pending';
COMMENT ON TABLE ai_request_log IS 'AI request metadata with retention. Never stores prompts, outputs, headers or keys.';

-- AI budget thresholds and unknown-price admissions as alert events.
ALTER TABLE alert_subscriptions DROP CONSTRAINT alert_subscriptions_event_key_check;
ALTER TABLE alert_subscriptions ADD CONSTRAINT alert_subscriptions_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending','ai_workload.static_key_expiring','ai.budget_threshold','ai.price_unknown'));
ALTER TABLE alert_deliveries DROP CONSTRAINT alert_deliveries_event_key_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending','ai_workload.static_key_expiring','ai.budget_threshold','ai.price_unknown'));
ALTER TABLE alert_delivery_cooldowns DROP CONSTRAINT alert_delivery_cooldowns_event_key_check;
ALTER TABLE alert_delivery_cooldowns ADD CONSTRAINT alert_delivery_cooldowns_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending','ai_workload.static_key_expiring','ai.budget_threshold','ai.price_unknown'));
ALTER TABLE alert_occurrences DROP CONSTRAINT alert_occurrences_event_key_check;
ALTER TABLE alert_occurrences ADD CONSTRAINT alert_occurrences_event_key_check CHECK (event_key IN ('agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift','gateway.offline','gateway.policy_degraded','site.link_down','device.offline','device.posture_blocked','kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable','ipsec.tunnel_down','ipsec.connection_down','ipsec.status_unavailable','agent.mcp_approval_pending','ai_workload.static_key_expiring','ai.budget_threshold','ai.price_unknown'));
