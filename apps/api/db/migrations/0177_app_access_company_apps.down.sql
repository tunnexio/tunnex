DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM app_access_requests) OR EXISTS(SELECT 1 FROM app_access_applications WHERE catalog_visible OR app_admin_user_id IS NOT NULL) THEN
  RAISE EXCEPTION 'App Access catalog assignments and request history are retained; rollback refused';
 END IF;
END $$;
DROP TABLE app_access_requests;
ALTER TABLE app_access_grants DROP CONSTRAINT app_access_grants_request_binding;
DROP TRIGGER app_access_admin_detached ON app_access_applications;
DROP FUNCTION app_access_admin_detached();
ALTER TABLE app_access_applications DROP CONSTRAINT app_access_admin_membership_fk,
 DROP COLUMN app_admin_user_id,DROP COLUMN catalog_visible;
