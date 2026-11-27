package mcptoolpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SystemActor attributes rows written on a gateway's report rather than by a person.
const SystemActor = "mcp-gateway"

// ErrEndpointNotAssigned means a gateway reported a server the agent has no profile for.
var ErrEndpointNotAssigned = errors.New("MCP endpoint is not assigned to the agent")

// RecordGatewayInventory stores what the agent's own gateway observed and makes the definition pin follow
// from it, in one transaction:
//
//   - every hash in the stored snapshot is computed here from the raw definitions;
//   - a rule saved before the pin existed is pinned to the definition first observed, provided the tool is
//     still the one the rule names (same server and input schema);
//   - a pinned rule whose observed definition moved is recorded once as `agent.mcp_tool_definition.changed`.
//
// The device must be an agent homed on nodeID and the endpoint must be the one its profile assigns.
func (s *Service) RecordGatewayInventory(ctx context.Context, orgID, nodeID, deviceID uuid.UUID, in GatewayObservation, now time.Time) error {
	if s == nil || s.pool == nil || orgID == uuid.Nil || nodeID == uuid.Nil || deviceID == uuid.Nil || in.Endpoint == "" || len(in.Endpoint) > 2048 {
		return ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM devices WHERE id=$1 AND org_id=$2 AND node_id=$3 AND kind='agent' AND deleted_at IS NULL FOR UPDATE`, deviceID, orgID, nodeID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	assigned, err := assignedEndpoints(ctx, tx, orgID, deviceID)
	if err != nil {
		return err
	}
	if !containsEndpoint(assigned, in.Endpoint) {
		return ErrEndpointNotAssigned
	}

	var priorRaw []byte
	var priorSource string
	var prior Inventory
	err = tx.QueryRow(ctx, `SELECT snapshot, source FROM agent_mcp_inventory WHERE device_id=$1 FOR UPDATE`, deviceID).Scan(&priorRaw, &priorSource)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	extras := map[string]json.RawMessage{}
	if err == nil {
		_ = json.Unmarshal(priorRaw, &extras)
		// Tools the agent host reported are never a baseline: only what a gateway saw before counts.
		if priorSource == SourceGateway {
			prior = parseInventory(priorRaw, priorSource, time.Time{})
		}
	}
	previous, hadPrevious := prior.Server(in.Endpoint)
	server := observedServer(in, previous, hadPrevious, now)

	if server.Status == StatusHealthy {
		if err := s.followDefinitions(ctx, tx, orgID, deviceID, server, previous, now); err != nil {
			return err
		}
	}

	// An agent can have several MCP servers and the gateway reports them one at a time: this observation
	// replaces only its own endpoint. What was seen for the agent's other assigned servers is kept, and a
	// server that is no longer assigned is dropped.
	merged := func(own InventoryServer) []InventoryServer {
		servers := []InventoryServer{own}
		for _, other := range prior.Servers {
			if other.Endpoint != in.Endpoint && containsEndpoint(assigned, other.Endpoint) {
				servers = append(servers, other)
			}
		}
		sort.Slice(servers, func(i, j int) bool { return servers[i].Endpoint < servers[j].Endpoint })
		return servers
	}
	snapshot := map[string]interface{}{"servers": merged(server)}
	// OAuth discovery metadata is not a tool list and has no gateway source yet; keep what is there.
	if discovery, ok := extras["oauth_discovery"]; ok {
		snapshot["oauth_discovery"] = discovery
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if len(raw) > maxSnapshotBytes {
		server.Status, server.Tools = "invalid", previous.Tools
		if !hadPrevious {
			server.Tools = []InventoryTool{}
		}
		snapshot["servers"] = merged(server)
		if raw, err = json.Marshal(snapshot); err != nil {
			return err
		}
		if len(raw) > maxSnapshotBytes {
			// The agent's servers together are too large to store: keep this one's status alone.
			server.Tools = []InventoryTool{}
			snapshot["servers"] = []InventoryServer{server}
			if raw, err = json.Marshal(snapshot); err != nil {
				return err
			}
		}
	}
	tag, err := tx.Exec(ctx, `INSERT INTO agent_mcp_inventory (device_id, snapshot, observed_at, source) VALUES ($1,$2::jsonb,$3,'gateway')
ON CONFLICT (device_id) DO UPDATE SET snapshot=EXCLUDED.snapshot, observed_at=EXCLUDED.observed_at, source='gateway'`, deviceID, raw, now.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// followDefinitions pins rules that have no definition hash yet and records definitions that moved.
func (s *Service) followDefinitions(ctx context.Context, tx pgx.Tx, orgID, deviceID uuid.UUID, server, previous InventoryServer, now time.Time) error {
	current, err := currentRules(ctx, tx, deviceID)
	if err != nil || current.Version == 0 {
		return err
	}
	pinned := 0
	for i := range current.Rules {
		rule := &current.Rules[i]
		if rule.Endpoint != server.Endpoint {
			continue
		}
		tool, ok := server.Tool(rule.ToolName)
		if !ok {
			continue
		}
		if rule.ToolDefinitionHash == "" && rule.ServerName == server.ServerName && rule.InputSchemaHash == tool.InputSchemaHash {
			rule.ToolDefinitionHash = tool.ToolDefinitionHash
			pinned++
			continue
		}
		if rule.ToolDefinitionHash == tool.ToolDefinitionHash {
			continue
		}
		// Record a move once: when this observation differs from the one before it.
		if before, seen := previous.Tool(rule.ToolName); seen && before.ToolDefinitionHash == tool.ToolDefinitionHash {
			continue
		}
		metadata, _ := json.Marshal(map[string]any{"endpoint": rule.Endpoint, "server_name": server.ServerName, "tool_name": rule.ToolName, "policy_version": current.Version, "pinned_definition_hash": rule.ToolDefinitionHash, "observed_definition_hash": tool.ToolDefinitionHash})
		if _, err := tx.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_system, action, target_type, target_id, metadata) VALUES ($1,$2,'agent.mcp_tool_definition.changed','agent',$3,$4)`, orgID, SystemActor, deviceID.String(), metadata); err != nil {
			return err
		}
	}
	if pinned == 0 {
		return nil
	}
	// Versions are immutable, so the pin is a new version. It keeps the author of the rules it copies and
	// is attributed to the system in the audit log.
	raw, err := json.Marshal(current.Rules)
	if err != nil {
		return err
	}
	version := current.Version + 1
	if _, err := tx.Exec(ctx, `INSERT INTO agent_mcp_tool_policy_versions (org_id, device_id, version, rules, inventory_observed_at, created_by_user_id, override_endpoints) VALUES ($1,$2,$3,$4,$5,$6,$7)`, orgID, deviceID, version, raw, now.UTC(), current.CreatedBy, mergeEndpoints(current.OverrideEndpoints, nil)); err != nil {
		return err
	}
	metadata, _ := json.Marshal(map[string]any{"version": version, "rule_count": len(current.Rules), "cause": "definition_pin", "pinned_rule_count": pinned, "inventory_observed_at": now.UTC().Format(time.RFC3339Nano)})
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_system, action, target_type, target_id, metadata) VALUES ($1,$2,'agent.mcp_tool_policy.replaced','agent',$3,$4)`, orgID, SystemActor, deviceID.String(), metadata)
	return err
}

// AcceptDefinition re-pins one rule to the definition the gateway observes now. The caller names the hash
// it reviewed; if the tool moved again since, nothing is written and ErrDefinitionStale is returned.
func (s *Service) AcceptDefinition(ctx context.Context, orgID, deviceID, actorID uuid.UUID, endpoint, toolName, definitionHash string) (Policy, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil || actorID == uuid.Nil || endpoint == "" || toolName == "" || !validDefinitionHash(definitionHash) {
		return Policy{}, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Policy{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM devices WHERE id=$1 AND org_id=$2 AND kind='agent' AND deleted_at IS NULL FOR UPDATE`, deviceID, orgID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Policy{}, ErrNotFound
		}
		return Policy{}, err
	}
	current, err := currentRules(ctx, tx, deviceID)
	if err != nil {
		return Policy{}, err
	}
	index := -1
	for i, rule := range current.Rules {
		if rule.Endpoint == endpoint && rule.ToolName == toolName {
			index = i
			break
		}
	}
	if index < 0 {
		return Policy{}, ErrRuleNotFound
	}
	inventory, err := loadInventory(ctx, tx, orgID, deviceID, " FOR SHARE OF i")
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Policy{}, err
	}
	server, _ := inventory.Server(endpoint)
	tool, ok := server.Tool(toolName)
	if inventory.Source != SourceGateway || server.Status != StatusHealthy || !ok || tool.ToolDefinitionHash != definitionHash {
		return Policy{}, ErrDefinitionStale
	}
	rule := current.Rules[index]
	before := rule.ToolDefinitionHash
	rule.ServerName, rule.InputSchemaHash, rule.ToolDefinitionHash = server.ServerName, tool.InputSchemaHash, tool.ToolDefinitionHash
	current.Rules[index] = rule
	rules := canonicalRules(current.Rules)
	if rules == nil {
		return Policy{}, ErrInvalid
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return Policy{}, err
	}
	version := current.Version + 1
	var created time.Time
	if err := tx.QueryRow(ctx, `INSERT INTO agent_mcp_tool_policy_versions (org_id, device_id, version, rules, inventory_observed_at, created_by_user_id, override_endpoints) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`, orgID, deviceID, version, raw, inventory.ObservedAt, actorID, mergeEndpoints(current.OverrideEndpoints, nil)).Scan(&created); err != nil {
		return Policy{}, err
	}
	metadata, _ := json.Marshal(map[string]any{"endpoint": endpoint, "server_name": server.ServerName, "tool_name": toolName, "version": version, "previous_definition_hash": before, "accepted_definition_hash": definitionHash})
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_user_id, action, target_type, target_id, metadata) VALUES ($1,$2,'agent.mcp_tool_definition.accepted','agent',$3,$4)`, orgID, actorID, deviceID.String(), metadata); err != nil {
		return Policy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Policy{}, err
	}
	annotateDefinitionState(rules, inventory)
	return Policy{Version: version, Rules: rules, InventoryObservedAt: inventory.ObservedAt, CreatedAt: created, OverrideEndpoints: mergeEndpoints(current.OverrideEndpoints, nil)}, nil
}
