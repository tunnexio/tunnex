-- Do not erase uploaded icons (including immutable historical revisions) during
-- a schema downgrade. Retain this schema with a compatible binary or restore a
-- verified pre-upgrade backup; older operator tools reject a newer schema.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM app_access_revisions WHERE icon_data_url <> '') THEN
  RAISE EXCEPTION 'App Access uploaded icons are retained; use a compatible binary or a verified pre-upgrade backup';
 END IF;
END $$;
ALTER TABLE app_access_revisions DROP COLUMN icon_data_url;
