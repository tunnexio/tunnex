-- name: ListAIGatewayTeamPolicies :many
SELECT team_id,models,key_ids,daily_cost_limit,revision FROM ai_gateway_team_policies WHERE org_id=$1 ORDER BY team_id;

-- name: ListAIGatewayAssignments :many
SELECT device_id,team_id,enabled,models_override,revision,applied_revision,applied_team_revision,status
FROM ai_gateway_assignments WHERE org_id=$1 ORDER BY device_id;

-- name: ListAIGatewayNativeBindings :many
SELECT device_id,team_id,native_key_id FROM ai_gateway_key_bindings WHERE org_id=$1 ORDER BY device_id,team_id;
