DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM alert_occurrences) THEN
        RAISE EXCEPTION '0126 rollback refused: alert occurrence history exists';
    END IF;
    IF EXISTS (
        SELECT 1 FROM alert_subscriptions WHERE event_key NOT LIKE 'agent.%'
        UNION ALL SELECT 1 FROM alert_deliveries WHERE event_key NOT LIKE 'agent.%'
        UNION ALL SELECT 1 FROM alert_delivery_cooldowns WHERE event_key NOT LIKE 'agent.%'
    ) THEN
        RAISE EXCEPTION '0126 rollback refused: cross-product alert data exists';
    END IF;
END $$;

DROP TABLE alert_occurrences;

ALTER TABLE alert_subscriptions DROP CONSTRAINT alert_subscriptions_event_key_check;
ALTER TABLE alert_deliveries DROP CONSTRAINT alert_deliveries_event_key_check;
ALTER TABLE alert_delivery_cooldowns DROP CONSTRAINT alert_delivery_cooldowns_event_key_check;

ALTER TABLE alert_subscriptions ADD CONSTRAINT alert_subscriptions_event_key_check CHECK (event_key IN (
    'agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift'
));
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_event_key_check CHECK (event_key IN (
    'agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift'
));
ALTER TABLE alert_delivery_cooldowns ADD CONSTRAINT alert_delivery_cooldowns_event_key_check CHECK (event_key IN (
    'agent.offline','agent.denial_spike','agent.access_expiring','agent.rotation_failed','agent.configuration_drift'
));
