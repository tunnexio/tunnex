CREATE TRIGGER set_updated_at BEFORE UPDATE ON server_access_servers
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER set_updated_at BEFORE UPDATE ON server_access_settings
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
