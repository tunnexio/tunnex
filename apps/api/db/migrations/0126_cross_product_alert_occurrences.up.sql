-- Cross-product alerts reuse F11's destination, SSRF, retry, and cooldown
-- machinery. This migration expands only the closed event vocabulary and adds
-- a tenant-scoped condition lifecycle that is independent of notification
-- opt-in and destination count.

ALTER TABLE alert_subscriptions DROP CONSTRAINT alert_subscriptions_event_key_check;
ALTER TABLE alert_deliveries DROP CONSTRAINT alert_deliveries_event_key_check;
ALTER TABLE alert_delivery_cooldowns DROP CONSTRAINT alert_delivery_cooldowns_event_key_check;

ALTER TABLE alert_subscriptions ADD CONSTRAINT alert_subscriptions_event_key_check CHECK (event_key IN (
    'agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift',
    'gateway.offline','gateway.policy_degraded','site.link_down',
    'device.offline','device.posture_blocked',
    'kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable'
));
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_event_key_check CHECK (event_key IN (
    'agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift',
    'gateway.offline','gateway.policy_degraded','site.link_down',
    'device.offline','device.posture_blocked',
    'kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable'
));
ALTER TABLE alert_delivery_cooldowns ADD CONSTRAINT alert_delivery_cooldowns_event_key_check CHECK (event_key IN (
    'agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift',
    'gateway.offline','gateway.policy_degraded','site.link_down',
    'device.offline','device.posture_blocked',
    'kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable'
));

CREATE TABLE alert_occurrences (
    id                 uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id             uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    event_key          text NOT NULL CHECK (event_key IN (
        'agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift',
        'gateway.offline','gateway.policy_degraded','site.link_down',
        'device.offline','device.posture_blocked',
        'kubernetes.connector_degraded','kubernetes.inventory_stale','kubernetes.service_unavailable'
    )),
    dedup_key          text NOT NULL CHECK (length(dedup_key) BETWEEN 1 AND 256),
    resource_type      text NOT NULL DEFAULT '' CHECK (resource_type IN ('','agent','gateway','site','device','kubernetes_cluster','kubernetes_service')),
    resource_id        text NOT NULL DEFAULT '' CHECK ((resource_type='' AND resource_id='') OR (resource_type<>'' AND length(btrim(resource_id)) BETWEEN 1 AND 255)),
    resource_name      text NOT NULL DEFAULT '' CHECK (length(resource_name) <= 255),
    severity           text NOT NULL CHECK (severity IN ('info','warning','critical')),
    subject            text NOT NULL CHECK (length(btrim(subject)) BETWEEN 1 AND 500),
    fields             jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(fields)='object'),
    state              text NOT NULL CHECK (state IN ('firing','resolved')),
    first_observed_at  timestamptz NOT NULL,
    last_observed_at   timestamptz NOT NULL,
    resolved_at        timestamptz,
    occurrence_count   bigint NOT NULL DEFAULT 0 CHECK (occurrence_count >= 0),
    UNIQUE (org_id,event_key,dedup_key),
    CHECK ((state='resolved' AND resolved_at IS NOT NULL) OR (state='firing' AND resolved_at IS NULL))
);
CREATE INDEX alert_occurrences_org_active_idx
    ON alert_occurrences (org_id,severity,last_observed_at DESC,id DESC) WHERE state='firing';
CREATE INDEX alert_occurrences_org_history_idx
    ON alert_occurrences (org_id,last_observed_at DESC,id DESC);
