-- F11 D7: one durable row per destination and condition carries the
-- suppression count between actual sends. It is alerting-local state, not a
-- general rate limiter and must not be reused outside internal/alerts.
CREATE TABLE alert_delivery_cooldowns (
    org_id           uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    destination_id   uuid NOT NULL,
    event_key        text NOT NULL CHECK (event_key IN ('agent.offline', 'agent.denial_spike', 'agent.access_expiring', 'agent.rotation_failed', 'agent.configuration_drift')),
    dedup_key        text NOT NULL CHECK (length(dedup_key) BETWEEN 1 AND 256),
    next_eligible_at timestamptz NOT NULL,
    suppressed_count integer NOT NULL DEFAULT 0 CHECK (suppressed_count >= 0),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (destination_id, event_key, dedup_key),
    FOREIGN KEY (destination_id, org_id)
        REFERENCES alert_destinations (id, org_id) ON DELETE RESTRICT
);
CREATE INDEX alert_delivery_cooldowns_org_id_idx
    ON alert_delivery_cooldowns (org_id, next_eligible_at, destination_id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON alert_delivery_cooldowns
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
