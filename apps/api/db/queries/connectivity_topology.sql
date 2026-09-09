-- name: ShareConnectivityHubSet :many
SELECT org_id FROM org_hub_set WHERE org_id=$1 FOR SHARE;

-- name: ShareConnectivityTopologyNodes :many
SELECT id FROM nodes WHERE org_id=$1 ORDER BY id FOR SHARE;

-- name: ShareConnectivityTopologySites :many
SELECT id FROM sites WHERE org_id=$1 ORDER BY id FOR SHARE;
