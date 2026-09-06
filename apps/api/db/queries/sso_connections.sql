-- name: ListSSOConnections :many
SELECT * FROM sso_connections WHERE org_id=$1 ORDER BY name,id;
-- name: GetSSOConnection :one
-- lint:cross-org — public login selects an explicit globally unique connection; no tenant guessing.
SELECT * FROM sso_connections WHERE id=$1;
-- name: LockSSOConnection :one
-- lint:cross-org — callback locks its opaque server-side flow's exact connection.
SELECT * FROM sso_connections WHERE id=$1 FOR UPDATE;
-- name: SaveSSOConnection :one
INSERT INTO sso_connections (id,org_id,name,provider,issuer_url,client_id,client_secret_sealed)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,provider=EXCLUDED.provider,
issuer_url=EXCLUDED.issuer_url,client_id=EXCLUDED.client_id,client_secret_sealed=EXCLUDED.client_secret_sealed,
enabled=false,revision=sso_connections.revision+1,tested_revision=NULL,tested_at=NULL
WHERE sso_connections.org_id=EXCLUDED.org_id
RETURNING *;
-- name: ActivateSSOConnection :one
UPDATE sso_connections SET enabled=$3 WHERE org_id=$1 AND id=$2 AND revision=$4
AND (NOT $3::boolean OR tested_revision=revision) RETURNING *;
-- name: VerifySSOConnection :execrows
-- lint:cross-org — callback validates the locked connection against its server-side flow and rechecks administrator membership before marking this exact revision tested.
UPDATE sso_connections SET tested_revision=revision,tested_at=now() WHERE id=$1 AND revision=$2;
-- name: GetSSOConnectionIdentity :one
-- lint:cross-org — identity namespace is the explicit connection plus issuer and subject; callback checks flow ownership, and directory sync resolves the connection from its tenant-scoped config.
SELECT user_id FROM sso_connection_identities WHERE connection_id=$1 AND issuer_url=$2 AND subject=$3;
-- name: LinkSSOConnectionIdentity :exec
INSERT INTO sso_connection_identities (connection_id,issuer_url,subject,user_id) VALUES ($1,$2,$3,$4);
-- name: HasSSOConnectionIdentities :one
-- lint:cross-org — SaveConnection checks the locked connection owner before inspecting this exact identity namespace.
SELECT EXISTS(SELECT 1 FROM sso_connection_identities WHERE connection_id=$1);

-- name: IsDirectoryManagedConnection :one
-- lint:cross-org — checks whether the already selected exact connection is directory managed; callers validate owner or server-side callback flow first.
SELECT EXISTS(SELECT 1 FROM idp_sync_configs WHERE sso_connection_id=$1);

-- name: IsDirectoryImportedIdentity :one
-- lint:cross-org — callback checks its locked connection and active organization membership before reading provenance for this exact issuer and subject.
SELECT directory_imported FROM sso_connection_identities WHERE connection_id=$1 AND issuer_url=$2 AND subject=$3;

-- name: ImportSSOConnectionIdentity :exec
INSERT INTO sso_connection_identities (connection_id,issuer_url,subject,user_id,directory_imported) VALUES ($1,$2,$3,$4,true);

-- name: ListPublicLoginConnections :many
-- lint:cross-org — minimal public login choices; explicit IDs prevent tenant guessing.
SELECT id,name,provider FROM sso_connections
WHERE enabled=true AND tested_revision=revision ORDER BY name,id;
