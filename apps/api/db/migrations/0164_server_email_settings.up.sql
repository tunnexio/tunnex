-- One deployment-wide override. Absence preserves installer/environment configuration.
CREATE TABLE server_email_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision bigint NOT NULL CHECK (revision > 0),
    config_ciphertext text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON server_email_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
