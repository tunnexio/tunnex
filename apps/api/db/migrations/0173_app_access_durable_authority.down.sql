DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM app_access_installation_authority) THEN
 RAISE EXCEPTION 'App Access installation authority is forward-only: schema173 rollback requires forward-compatible recovery; retained Redis authority cannot be observed by a database downgrade'; END IF;
 IF EXISTS(SELECT 1 FROM app_access_session_revocations) OR EXISTS(SELECT 1 FROM app_access_events) THEN RAISE EXCEPTION 'retained App Access durable authority prevents rollback'; END IF;
END $$;
DROP TABLE app_access_events;
DROP TABLE app_access_session_revocations;
DROP FUNCTION app_access_session_revocation_immutable();
DROP TABLE app_access_installation_authority;
