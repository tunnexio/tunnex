-- Preservation first: rollback is safe only before an organization enables
-- alerting or records destinations/deliveries. PostgreSQL executes this file
-- transactionally, so refusal leaves the F11 schema and its rows untouched.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM organizations WHERE alerting_enabled)
       OR EXISTS (SELECT 1 FROM alert_delivery_attempts)
       OR EXISTS (SELECT 1 FROM alert_deliveries)
       OR EXISTS (SELECT 1 FROM alert_subscriptions)
       OR EXISTS (SELECT 1 FROM alert_destinations) THEN
        RAISE EXCEPTION 'cannot roll back 0099: alerting state exists';
    END IF;
END;
$$;

DROP TRIGGER alert_delivery_attempts_no_truncate ON alert_delivery_attempts;
DROP TRIGGER alert_delivery_attempts_no_delete ON alert_delivery_attempts;
DROP TRIGGER alert_delivery_attempts_no_update ON alert_delivery_attempts;
DROP FUNCTION alert_delivery_attempts_prevent_mutation();
DROP TABLE alert_delivery_attempts;
DROP TABLE alert_deliveries;
DROP TABLE alert_subscriptions;
DROP TABLE alert_destinations;
ALTER TABLE organizations DROP COLUMN alerting_enabled;
