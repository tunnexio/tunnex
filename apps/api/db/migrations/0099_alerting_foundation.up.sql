-- F11: tenant-scoped alert destinations and a durable delivery outbox. Secrets
-- are sealed by the service before insert; only a keyed fingerprint and display
-- host are ever safe to return to a caller.

ALTER TABLE organizations
    ADD COLUMN alerting_enabled boolean NOT NULL DEFAULT false;

CREATE TABLE alert_destinations (
    id                   uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id               uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    kind                 text NOT NULL CHECK (kind IN ('slack', 'teams', 'pagerduty', 'opsgenie', 'discord', 'google_chat', 'webhook', 'email')),
    name                 text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    endpoint_sealed      bytea NOT NULL CHECK (octet_length(endpoint_sealed) > 0),
    endpoint_fingerprint text NOT NULL CHECK (endpoint_fingerprint ~ '^[0-9a-f]{12}$'),
    endpoint_host        text NOT NULL CHECK (length(btrim(endpoint_host)) BETWEEN 1 AND 255),
    allow_private        boolean NOT NULL DEFAULT false,
    severity_floor       text NOT NULL DEFAULT 'warning' CHECK (severity_floor IN ('info', 'warning', 'critical')),
    cooldown_seconds     integer NOT NULL DEFAULT 900 CHECK (cooldown_seconds BETWEEN 60 AND 86400),
    archived_at          timestamptz,
    created_by_user_id   uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id)
);
CREATE UNIQUE INDEX alert_destinations_org_active_name_key
    ON alert_destinations (org_id, lower(name)) WHERE archived_at IS NULL;
CREATE INDEX alert_destinations_org_id_idx
    ON alert_destinations (org_id, created_at, id);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON alert_destinations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE alert_subscriptions (
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    destination_id  uuid NOT NULL,
    event_key       text NOT NULL CHECK (event_key IN ('agent.offline', 'agent.denial_spike', 'agent.access_expiring', 'agent.rotation_failed', 'agent.configuration_drift')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (destination_id, event_key),
    FOREIGN KEY (destination_id, org_id)
        REFERENCES alert_destinations (id, org_id) ON DELETE RESTRICT
);
CREATE INDEX alert_subscriptions_org_event_idx
    ON alert_subscriptions (org_id, event_key, destination_id);

CREATE TABLE alert_deliveries (
    id               uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id           uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    destination_id   uuid NOT NULL,
    event_key        text NOT NULL CHECK (event_key IN ('agent.offline', 'agent.denial_spike', 'agent.access_expiring', 'agent.rotation_failed', 'agent.configuration_drift')),
    severity         text NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    dedup_key        text NOT NULL CHECK (length(dedup_key) BETWEEN 1 AND 256),
    payload          jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    state            text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivering', 'sent', 'failed', 'suppressed')),
    attempts         integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_error       text,
    suppressed_count integer NOT NULL DEFAULT 0 CHECK (suppressed_count >= 0),
    sent_at          timestamptz,
    failed_at        timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id),
    FOREIGN KEY (destination_id, org_id)
        REFERENCES alert_destinations (id, org_id) ON DELETE RESTRICT,
    CHECK ((state = 'sent' AND sent_at IS NOT NULL AND failed_at IS NULL)
        OR (state = 'failed' AND failed_at IS NOT NULL AND sent_at IS NULL)
        OR (state NOT IN ('sent', 'failed') AND sent_at IS NULL AND failed_at IS NULL))
);
CREATE INDEX alert_deliveries_due_idx
    ON alert_deliveries (next_attempt_at, id) WHERE state = 'pending';
CREATE INDEX alert_deliveries_org_destination_idx
    ON alert_deliveries (org_id, destination_id, created_at DESC, id DESC);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON alert_deliveries
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE alert_delivery_attempts (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    delivery_id     uuid NOT NULL,
    attempt         integer NOT NULL CHECK (attempt BETWEEN 1 AND 10),
    outcome         text NOT NULL CHECK (outcome IN ('sent', 'retryable_failure', 'terminal_failure', 'suppressed')),
    response_status integer CHECK (response_status BETWEEN 100 AND 599),
    error           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (delivery_id, attempt),
    FOREIGN KEY (delivery_id, org_id)
        REFERENCES alert_deliveries (id, org_id) ON DELETE RESTRICT
);
CREATE INDEX alert_delivery_attempts_org_delivery_idx
    ON alert_delivery_attempts (org_id, delivery_id, attempt);

CREATE FUNCTION alert_delivery_attempts_prevent_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'alert_delivery_attempts is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER alert_delivery_attempts_no_update
    BEFORE UPDATE ON alert_delivery_attempts
    FOR EACH ROW EXECUTE FUNCTION alert_delivery_attempts_prevent_mutation();
CREATE TRIGGER alert_delivery_attempts_no_delete
    BEFORE DELETE ON alert_delivery_attempts
    FOR EACH ROW EXECUTE FUNCTION alert_delivery_attempts_prevent_mutation();
CREATE TRIGGER alert_delivery_attempts_no_truncate
    BEFORE TRUNCATE ON alert_delivery_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION alert_delivery_attempts_prevent_mutation();
