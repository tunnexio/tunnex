DO $$ BEGIN IF EXISTS(SELECT 1 FROM app_access_proxy_credentials) OR EXISTS(SELECT 1 FROM app_access_serving_publications) THEN RAISE EXCEPTION 'App Access proxy authority history exists; refusing destructive down migration'; END IF; END $$;
DROP TABLE app_access_serving_publications;
DROP TABLE app_access_proxy_credentials;
