-- Retention settings and run history are operator-visible state. Refuse a
-- destructive rollback once either table has been used.
LOCK TABLE access_event_retention_runs,
           access_event_retention_settings
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM access_event_retention_settings)
       OR EXISTS (SELECT 1 FROM access_event_retention_runs) THEN
        RAISE EXCEPTION 'cannot roll back 0127: access-event retention state exists';
    END IF;
END;
$$;

DROP TABLE access_event_retention_runs;
DROP FUNCTION access_event_retention_run_actor_require_membership();
DROP TABLE access_event_retention_settings;
DROP FUNCTION access_event_retention_settings_actor_require_membership();
