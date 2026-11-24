-- SA-UI-1: installation-wide Server Access capability, managed by server administrators.
-- An absent row preserves the environment seed (TUNNEX_SERVER_ACCESS_ENABLED); the first save
-- writes the row and from then on the saved value wins. TUNNEX_SERVER_ACCESS_LOCKED still forces off.
CREATE TABLE server_access_installation_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled boolean NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    updated_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON server_access_installation_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
