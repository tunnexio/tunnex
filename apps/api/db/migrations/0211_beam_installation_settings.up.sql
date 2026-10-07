-- Installation authority is independent of environment hints and organization policy.
CREATE TABLE beam_installation_settings (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 configured boolean NOT NULL DEFAULT false,
 operator_enabled boolean NOT NULL DEFAULT false,
 base_domain text NOT NULL DEFAULT '', proxy_url text NOT NULL DEFAULT '', portal_url text NOT NULL DEFAULT '',
 readiness_version text NOT NULL DEFAULT '', readiness_passed boolean NOT NULL DEFAULT false,
 readiness_checked_at timestamptz, readiness_expires_at timestamptz,
 readiness_checks jsonb NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(readiness_checks)='array'),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK(NOT readiness_passed OR (configured AND operator_enabled AND readiness_version ~ '^[0-9a-f]{64}$' AND readiness_checked_at IS NOT NULL AND readiness_expires_at IS NOT NULL AND readiness_expires_at>readiness_checked_at))
);
INSERT INTO beam_installation_settings(singleton) VALUES(true);
CREATE TRIGGER set_updated_at BEFORE UPDATE ON beam_installation_settings FOR EACH ROW EXECUTE FUNCTION set_updated_at();
