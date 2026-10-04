DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM app_access_publication_operations) OR EXISTS(SELECT 1 FROM app_access_applications WHERE state='archived') OR EXISTS(SELECT 1 FROM app_access_origin_checks WHERE completed_cert_serial<>'') OR EXISTS(SELECT 1 FROM app_access_serving_publications WHERE withdrawal_confirmed_at IS NOT NULL) THEN
 RAISE EXCEPTION 'retained App Access publication authority prevents rollback'; END IF;
END $$;
ALTER TABLE app_access_serving_publications DROP CONSTRAINT app_access_withdrawal_confirmation;
ALTER TABLE app_access_serving_publications DROP COLUMN withdrawal_confirmed_at;
ALTER TABLE app_access_serving_publications DROP COLUMN withdrawal_confirmed_authority_version;
ALTER TABLE app_access_serving_publications DROP COLUMN withdrawal_confirmed_generation;
DROP TABLE app_access_publication_operations;
DROP FUNCTION app_access_publication_operation_immutable();
DROP TABLE app_access_browser_gateway_runtime;
ALTER TABLE app_access_revisions DROP CONSTRAINT app_access_revision_publication_host;
ALTER TABLE app_access_origin_checks DROP CONSTRAINT app_access_check_publication_tuple;
ALTER TABLE app_access_origin_checks DROP COLUMN completed_cert_serial;
ALTER TABLE app_access_applications DROP CONSTRAINT app_access_applications_state_check;
ALTER TABLE app_access_applications ADD CONSTRAINT app_access_applications_state_check CHECK(state='draft');
