-- F15: device-bound public signing keys. A key ID is immutable once enrolled;
-- replacement is a future explicit rotation, never an upsert of trust material.

-- name: CreateAgentWorkflowSigningKey :one
INSERT INTO agent_workflow_signing_keys (org_id, device_id, key_id, public_key)
SELECT sqlc.arg(org_id), d.id, sqlc.arg(key_id), sqlc.arg(public_key)
FROM devices d
WHERE d.id = sqlc.arg(device_id)
  AND d.org_id = sqlc.arg(org_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
ON CONFLICT (device_id, key_id) DO NOTHING
RETURNING *;

-- name: GetAgentWorkflowSigningKey :one
SELECT * FROM agent_workflow_signing_keys
WHERE org_id = sqlc.arg(org_id)
  AND device_id = sqlc.arg(device_id)
  AND key_id = sqlc.arg(key_id);

-- name: ClaimAgentWorkflowAssertion :one
INSERT INTO agent_workflow_provenance_used_assertions (device_id, assertion_id)
VALUES (sqlc.arg(device_id), sqlc.arg(assertion_id))
ON CONFLICT DO NOTHING
RETURNING device_id, assertion_id, claimed_at;

-- name: CreateAgentWorkflowProvenance :one
INSERT INTO agent_workflow_provenance (
  id, org_id, device_id, assertion_id, key_id, workflow_id, run_id, trigger_kind,
  initiating_subject_ref, tool, resource, issued_at, expires_at, signature,
  verification_state, verification_reason
) VALUES (
  sqlc.arg(id), sqlc.arg(org_id), sqlc.arg(device_id), sqlc.arg(assertion_id),
  sqlc.arg(key_id), sqlc.narg(workflow_id), sqlc.narg(run_id), sqlc.narg(trigger_kind),
  sqlc.narg(initiating_subject_ref), sqlc.narg(tool), sqlc.narg(resource),
  sqlc.narg(issued_at), sqlc.narg(expires_at), sqlc.narg(signature),
  sqlc.arg(verification_state), sqlc.arg(verification_reason)
) RETURNING *;

-- name: ListAgentWorkflowProvenance :many
SELECT * FROM agent_workflow_provenance
WHERE org_id = sqlc.arg(org_id) AND device_id = sqlc.arg(device_id)
ORDER BY received_at DESC, id DESC
LIMIT sqlc.arg(page_size);
