DO $$ BEGIN IF EXISTS(SELECT 1 FROM app_access_grants) THEN RAISE EXCEPTION 'App Access grant history exists; refusing destructive down migration'; END IF; END $$;
DROP TABLE app_access_grants;
DROP FUNCTION app_access_grant_subject_change();
