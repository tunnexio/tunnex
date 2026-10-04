-- Use the shared timestamp convention without rewriting existing rows.
-- Match the tenant-first lock order used by App Access lifecycle migrations.
LOCK TABLE organizations IN EXCLUSIVE MODE;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON app_access_applications
 FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER set_updated_at BEFORE UPDATE ON app_access_grants
 FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER set_updated_at BEFORE UPDATE ON app_access_serving_publications
 FOR EACH ROW EXECUTE FUNCTION set_updated_at();
