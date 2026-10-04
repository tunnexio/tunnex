-- Do not silently erase reviewed history. Empty-schema rollback remains possible.
DO $$ BEGIN IF EXISTS (SELECT 1 FROM app_access_applications) THEN RAISE EXCEPTION 'App Access history exists; refusing destructive down migration'; END IF; END $$;
ALTER TABLE app_access_applications DROP CONSTRAINT app_access_draft_revision_fk;
DROP TABLE app_access_revisions;
DROP TABLE app_access_hostnames;
DROP FUNCTION app_access_revision_immutable();
DROP TABLE app_access_applications;
DROP TABLE app_access_settings;
