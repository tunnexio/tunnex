-- Deployment-wide, explicit opt-in. Existing HTTP installations stay denied.
CREATE TABLE server_ai_transport_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    allow_http boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO server_ai_transport_settings (singleton) VALUES (true);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON server_ai_transport_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
