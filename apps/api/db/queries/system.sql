-- name: GenerateID :one
-- Returns a fresh time-ordered UUIDv7 from the database. Demonstrates the sqlc
-- pipeline and the uuid override; callers may also generate v7 ids in Go.
SELECT uuid_generate_v7() AS id;

-- name: GetSystemSetting :one
SELECT value FROM system_settings WHERE key = $1;

-- name: UpsertSystemSetting :exec
INSERT INTO system_settings (key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
