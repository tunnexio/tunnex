-- name: GetServerAccessInstallationSettings :one
-- SA-UI-1: the saved installation capability. No row = environment seed.
SELECT enabled, version, updated_at FROM server_access_installation_settings WHERE singleton;

-- name: LockServerAccessInstallationSettings :exec
-- Serializes saves, including the very first one when no row exists yet.
SELECT pg_advisory_xact_lock(175100402);

-- name: UpsertServerAccessInstallationSettings :one
INSERT INTO server_access_installation_settings (singleton, enabled, version, updated_by)
VALUES (true, @enabled, @version, @updated_by)
ON CONFLICT (singleton) DO UPDATE SET enabled = EXCLUDED.enabled, version = EXCLUDED.version, updated_by = EXCLUDED.updated_by
RETURNING enabled, version, updated_at;
