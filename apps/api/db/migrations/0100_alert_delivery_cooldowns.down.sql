-- A cooldown counter is product state. Refuse rather than discard suppressed
-- alert history during rollback.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM alert_delivery_cooldowns) THEN
        RAISE EXCEPTION 'cannot roll back 0100: alert delivery cooldown state exists';
    END IF;
END;
$$;

DROP TRIGGER set_updated_at ON alert_delivery_cooldowns;
DROP TABLE alert_delivery_cooldowns;
