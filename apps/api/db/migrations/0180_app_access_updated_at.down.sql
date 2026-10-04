LOCK TABLE organizations IN EXCLUSIVE MODE;
DROP TRIGGER set_updated_at ON app_access_serving_publications;
DROP TRIGGER set_updated_at ON app_access_grants;
DROP TRIGGER set_updated_at ON app_access_applications;
