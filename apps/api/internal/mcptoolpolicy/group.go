package mcptoolpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// What an administrator chooses for one tool. A rule with no approval step is Allow, a rule with one is
// Ask first, and no rule is Off: a tool nobody chose is Off by construction.
const (
	ModeAllow = "allow"
	ModeAsk   = "ask"
	ModeOff   = "off"
)

// Markers an administrator sets on a tool. Nothing is inferred from the tool's name.
const (
	EffectReads       = "reads"
	EffectChanges     = "changes"
	EffectDestructive = "destructive"
)

var (
	// ErrServerNotFound means the MCP server is not assigned to the agent group.
	ErrServerNotFound = errors.New("MCP server is not assigned to the agent group")
	// ErrOverrideNotFound means the agent's own policy does not decide for the endpoint.
	ErrOverrideNotFound = errors.New("the agent's policy does not override the MCP server")
	// ErrNoToolList means a tool was to be allowed and no usable tool list exists to check it against.
	ErrNoToolList = errors.New("no current tool list for the MCP server")
)

// ToolSetting is one tool as an administrator saves it.
type ToolSetting struct {
	ToolName string
	Mode     string
	// Effect is the marker; empty clears it.
	Effect string
	// ToolDefinitionHash is the definition the administrator was shown. Empty pins the one observed now.
	ToolDefinitionHash  string
	ArgumentConstraints json.RawMessage
	RateLimitPerMinute  *int
}

// GroupTool is one tool of a group's policy as it is shown.
type GroupTool struct {
	ToolName            string
	Description         string
	Mode                string
	Effect              string
	Observed            bool
	InputSchemaHash     string
	ToolDefinitionHash  string
	DefinitionState     string
	ArgumentConstraints json.RawMessage
	RateLimitPerMinute  *int
}

// GroupPolicy is an agent group's tool policy for one MCP server. Version 0 means none was saved.
type GroupPolicy struct {
	GroupID             uuid.UUID
	ProfileID           uuid.UUID
	ServerName          string
	Endpoint            string
	Version             int64
	Tools               []GroupTool
	InventoryObservedAt *time.Time
	CreatedAt           *time.Time
	OverridingAgents    int
}

type txQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// groupServer returns the server name and endpoint of a profile actively assigned to a group. With lock
// it takes the group's row lock, which serializes policy versions for the group.
func groupServer(ctx context.Context, q txQuerier, orgID, groupID, profileID uuid.UUID, lock bool) (serverName, endpoint string, err error) {
	sql := `SELECT p.server_name, btrim(p.endpoint) FROM agent_groups g
JOIN agent_mcp_profile_assignments a ON a.org_id=g.org_id AND a.agent_group_id=g.id AND a.state='active'
JOIN agent_mcp_profiles p ON p.id=a.profile_id AND p.org_id=a.org_id
WHERE g.org_id=$1 AND g.id=$2 AND p.id=$3 AND g.archived_at IS NULL`
	if lock {
		sql += ` FOR UPDATE OF g`
	}
	err = q.QueryRow(ctx, sql, orgID, groupID, profileID).Scan(&serverName, &endpoint)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrServerNotFound
	}
	return serverName, endpoint, err
}

// groupObservation returns the newest gateway observation of an endpoint among the group's agents. With
// fresh it accepts only a healthy observation young enough to back a decision; without, it returns the
// newest one of any status, for display.
func groupObservation(ctx context.Context, q txQuerier, orgID, groupID uuid.UUID, endpoint string, now time.Time, fresh bool) (InventoryServer, time.Time, bool, error) {
	rows, err := q.Query(ctx, `SELECT i.snapshot, i.observed_at FROM agent_mcp_inventory i
JOIN agent_group_members m ON m.device_id=i.device_id
JOIN devices d ON d.id=i.device_id AND d.org_id=m.org_id
WHERE m.org_id=$1 AND m.agent_group_id=$2 AND i.source='gateway' AND d.kind='agent' AND d.deleted_at IS NULL
ORDER BY i.observed_at DESC LIMIT 64`, orgID, groupID)
	if err != nil {
		return InventoryServer{}, time.Time{}, false, err
	}
	defer rows.Close()
	var best InventoryServer
	var bestAt time.Time
	found := false
	for rows.Next() {
		var snapshot []byte
		var observed time.Time
		if err := rows.Scan(&snapshot, &observed); err != nil {
			return InventoryServer{}, time.Time{}, false, err
		}
		server, ok := parseInventory(snapshot, SourceGateway, observed).Server(endpoint)
		if !ok {
			continue
		}
		seen := observed
		if at, err := time.Parse(time.RFC3339Nano, server.ObservedAt); err == nil {
			seen = at
		}
		if fresh && (server.Status != StatusHealthy || now.Sub(seen) > InventoryFreshness || seen.After(now.Add(time.Minute))) {
			continue
		}
		if !found || seen.After(bestAt) {
			best, bestAt, found = server, seen, true
		}
	}
	return best, bestAt, found, rows.Err()
}

// buildGroupRules turns the chosen tools into rules pinned to the definitions in server. Off tools make
// no rule. requireHash refuses an Allow or Ask first tool that does not say which definition was shown.
func buildGroupRules(endpoint string, server InventoryServer, tools []ToolSetting, requireHash bool) ([]Rule, error) {
	if len(tools) > 1024 {
		return nil, ErrInvalid
	}
	seen := make(map[string]bool, len(tools))
	rules := make([]Rule, 0, len(tools))
	for _, setting := range tools {
		name := setting.ToolName
		if name == "" || strings.TrimSpace(name) != name || len(name) > 512 || seen[name] {
			return nil, ErrInvalid
		}
		seen[name] = true
		switch setting.Effect {
		case "", EffectReads, EffectChanges, EffectDestructive:
		default:
			return nil, ErrInvalid
		}
		switch setting.Mode {
		case ModeOff:
			continue
		case ModeAllow, ModeAsk:
		default:
			return nil, ErrInvalid
		}
		if setting.ToolDefinitionHash != "" && !validDefinitionHash(setting.ToolDefinitionHash) {
			return nil, ErrInvalid
		}
		if requireHash && setting.ToolDefinitionHash == "" {
			return nil, ErrInvalid
		}
		tool, ok := server.Tool(name)
		if !ok {
			return nil, ErrUnobservedTool
		}
		if tool.ToolDefinitionHash == "" || server.ServerName == "" {
			return nil, ErrUnobservedTool
		}
		if setting.ToolDefinitionHash != "" && setting.ToolDefinitionHash != tool.ToolDefinitionHash {
			return nil, ErrDefinitionStale
		}
		rules = append(rules, Rule{Endpoint: endpoint, ServerName: server.ServerName, ToolName: name, InputSchemaHash: tool.InputSchemaHash,
			ArgumentConstraints: setting.ArgumentConstraints, RateLimitPerMinute: setting.RateLimitPerMinute, StepUpRequired: setting.Mode == ModeAsk, ToolDefinitionHash: tool.ToolDefinitionHash})
	}
	rules = canonicalRules(rules)
	if rules == nil {
		return nil, ErrInvalid
	}
	return rules, nil
}

func needsToolList(tools []ToolSetting) bool {
	for _, setting := range tools {
		if setting.Mode != ModeOff {
			return true
		}
	}
	return false
}

type groupWrite struct {
	OrgID, GroupID, ProfileID, ActorID uuid.UUID
	Endpoint                           string
	Tools                              []ToolSetting
	PreviewID                          *uuid.UUID
	Now                                time.Time
}

// replaceGroupTx writes the next policy version for (group, profile) and the markers, with their audit
// rows, inside the caller's transaction. The caller holds the group's row lock.
//
// Rules are checked against, and pinned to, a current gateway observation of the endpoint by any agent
// of the group. When there is none yet (the server is being connected), the connection preview the
// administrator chose from is used instead.
func replaceGroupTx(ctx context.Context, tx pgx.Tx, in groupWrite) (version int64, err error) {
	server, observedAt, ok, err := groupObservation(ctx, tx, in.OrgID, in.GroupID, in.Endpoint, in.Now, true)
	if err != nil {
		return 0, err
	}
	fromPreview := false
	if !ok && in.PreviewID != nil {
		if server, observedAt, ok, err = previewObservation(ctx, tx, in.OrgID, *in.PreviewID, in.Endpoint); err != nil {
			return 0, err
		}
		fromPreview = ok
	}
	if !ok {
		if needsToolList(in.Tools) {
			return 0, ErrNoToolList
		}
		observedAt = in.Now
	}
	rules, err := buildGroupRules(in.Endpoint, server, in.Tools, fromPreview)
	if err != nil {
		return 0, err
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return 0, err
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0)+1 FROM agent_group_mcp_tool_policy_versions WHERE org_id=$1 AND agent_group_id=$2 AND profile_id=$3`, in.OrgID, in.GroupID, in.ProfileID).Scan(&version); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_group_mcp_tool_policy_versions (org_id, agent_group_id, profile_id, version, rules, inventory_observed_at, created_by_user_id) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)`,
		in.OrgID, in.GroupID, in.ProfileID, version, raw, observedAt.UTC(), in.ActorID); err != nil {
		return 0, err
	}
	asks := 0
	for _, rule := range rules {
		if rule.StepUpRequired {
			asks++
		}
	}
	metadata, _ := json.Marshal(map[string]any{"profile_id": in.ProfileID.String(), "endpoint": in.Endpoint, "version": version, "allowed_tool_count": len(rules) - asks, "ask_first_tool_count": asks})
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_user_id, action, target_type, target_id, metadata) VALUES ($1,$2,'agent_group.mcp_tool_policy_replaced','agent_group',$3,$4)`, in.OrgID, in.ActorID, in.GroupID.String(), metadata); err != nil {
		return 0, err
	}
	return version, setMarkersTx(ctx, tx, in)
}

// setMarkersTx saves the marker of every listed tool and records each one that changed. A tool that is
// not listed keeps its marker.
func setMarkersTx(ctx context.Context, tx pgx.Tx, in groupWrite) error {
	current, err := loadMarkers(ctx, tx, in.OrgID, in.ProfileID)
	if err != nil {
		return err
	}
	for _, setting := range in.Tools {
		before := current[setting.ToolName]
		if before == setting.Effect {
			continue
		}
		var effect any = setting.Effect
		if setting.Effect == "" {
			effect = nil
			if _, err := tx.Exec(ctx, `DELETE FROM agent_mcp_tool_markers WHERE org_id=$1 AND profile_id=$2 AND tool_name=$3`, in.OrgID, in.ProfileID, setting.ToolName); err != nil {
				return err
			}
		} else if _, err := tx.Exec(ctx, `INSERT INTO agent_mcp_tool_markers (org_id, profile_id, tool_name, effect, set_by_user_id) VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (profile_id, tool_name) DO UPDATE SET effect=EXCLUDED.effect, set_by_user_id=EXCLUDED.set_by_user_id WHERE agent_mcp_tool_markers.org_id=EXCLUDED.org_id`, in.OrgID, in.ProfileID, setting.ToolName, setting.Effect, in.ActorID); err != nil {
			return err
		}
		metadata, _ := json.Marshal(map[string]any{"tool_name": setting.ToolName, "effect": effect, "endpoint": in.Endpoint})
		if _, err := tx.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_user_id, action, target_type, target_id, metadata) VALUES ($1,$2,'agent.mcp_tool_marker_set','agent_mcp_profile',$3,$4)`, in.OrgID, in.ActorID, in.ProfileID.String(), metadata); err != nil {
			return err
		}
	}
	return nil
}

func loadMarkers(ctx context.Context, q txQuerier, orgID, profileID uuid.UUID) (map[string]string, error) {
	rows, err := q.Query(ctx, `SELECT tool_name, effect FROM agent_mcp_tool_markers WHERE org_id=$1 AND profile_id=$2`, orgID, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, effect string
		if err := rows.Scan(&name, &effect); err != nil {
			return nil, err
		}
		out[name] = effect
	}
	return out, rows.Err()
}

// ReplaceGroup writes the next immutable tool policy version for an agent group and one of its MCP
// servers. It applies to every agent of the group whose own policy does not override that server.
func (s *Service) ReplaceGroup(ctx context.Context, orgID, groupID, profileID, actorID uuid.UUID, tools []ToolSetting) (GroupPolicy, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || groupID == uuid.Nil || profileID == uuid.Nil || actorID == uuid.Nil {
		return GroupPolicy{}, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return GroupPolicy{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, endpoint, err := groupServer(ctx, tx, orgID, groupID, profileID, true)
	if err != nil {
		return GroupPolicy{}, err
	}
	if _, err := replaceGroupTx(ctx, tx, groupWrite{OrgID: orgID, GroupID: groupID, ProfileID: profileID, ActorID: actorID, Endpoint: endpoint, Tools: tools, Now: time.Now().UTC()}); err != nil {
		return GroupPolicy{}, err
	}
	out, err := readGroup(ctx, tx, orgID, groupID, profileID, time.Now().UTC())
	if err != nil {
		return GroupPolicy{}, err
	}
	return out, tx.Commit(ctx)
}

// GetGroup returns an agent group's tool policy for one MCP server: every tool the gateway observes on
// the server with its mode and marker, plus tools the policy names that are no longer observed.
func (s *Service) GetGroup(ctx context.Context, orgID, groupID, profileID uuid.UUID) (GroupPolicy, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || groupID == uuid.Nil || profileID == uuid.Nil {
		return GroupPolicy{}, ErrInvalid
	}
	return readGroup(ctx, s.pool, orgID, groupID, profileID, time.Now().UTC())
}

func readGroup(ctx context.Context, q txQuerier, orgID, groupID, profileID uuid.UUID, now time.Time) (GroupPolicy, error) {
	serverName, endpoint, err := groupServer(ctx, q, orgID, groupID, profileID, false)
	if err != nil {
		return GroupPolicy{}, err
	}
	out := GroupPolicy{GroupID: groupID, ProfileID: profileID, ServerName: serverName, Endpoint: endpoint, Tools: []GroupTool{}}
	var rules []Rule
	var raw []byte
	var observedAt, createdAt time.Time
	err = q.QueryRow(ctx, `SELECT version, rules, inventory_observed_at, created_at FROM agent_group_mcp_tool_policy_versions
WHERE org_id=$1 AND agent_group_id=$2 AND profile_id=$3 ORDER BY version DESC LIMIT 1`, orgID, groupID, profileID).Scan(&out.Version, &raw, &observedAt, &createdAt)
	switch {
	case err == nil:
		if json.Unmarshal(raw, &rules) != nil {
			return GroupPolicy{}, ErrInvalid
		}
		out.InventoryObservedAt, out.CreatedAt = &observedAt, &createdAt
	case !errors.Is(err, pgx.ErrNoRows):
		return GroupPolicy{}, err
	}
	server, _, observed, err := groupObservation(ctx, q, orgID, groupID, endpoint, now, false)
	if err != nil {
		return GroupPolicy{}, err
	}
	markers, err := loadMarkers(ctx, q, orgID, profileID)
	if err != nil {
		return GroupPolicy{}, err
	}
	byTool := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		if rule.Endpoint == endpoint {
			byTool[rule.ToolName] = rule
		}
	}
	listed := map[string]bool{}
	add := func(tool GroupTool) {
		tool.Mode = ModeOff
		if rule, ok := byTool[tool.ToolName]; ok {
			tool.Mode = ModeAllow
			if rule.StepUpRequired {
				tool.Mode = ModeAsk
			}
			tool.ArgumentConstraints, tool.RateLimitPerMinute = rule.ArgumentConstraints, rule.RateLimitPerMinute
			if tool.Observed && server.Status == StatusHealthy {
				tool.DefinitionState = DefinitionChanged
				if rule.ToolDefinitionHash != "" && rule.ToolDefinitionHash == tool.ToolDefinitionHash && rule.ServerName == server.ServerName {
					tool.DefinitionState = DefinitionCurrent
				}
			}
			if !tool.Observed {
				tool.InputSchemaHash, tool.ToolDefinitionHash = rule.InputSchemaHash, rule.ToolDefinitionHash
			}
		}
		tool.Effect = markers[tool.ToolName]
		listed[tool.ToolName] = true
		out.Tools = append(out.Tools, tool)
	}
	if observed {
		for _, tool := range server.Tools {
			add(GroupTool{ToolName: tool.Name, Description: tool.Description, Observed: true, InputSchemaHash: tool.InputSchemaHash, ToolDefinitionHash: tool.ToolDefinitionHash})
		}
	}
	for name := range byTool {
		if !listed[name] {
			add(GroupTool{ToolName: name})
		}
	}
	sort.Slice(out.Tools, func(i, j int) bool { return out.Tools[i].ToolName < out.Tools[j].ToolName })
	if err := q.QueryRow(ctx, `SELECT count(*) FROM agent_group_members m
WHERE m.org_id=$1 AND m.agent_group_id=$2 AND EXISTS (
  SELECT 1 FROM agent_mcp_tool_policy_versions v
  WHERE v.org_id=m.org_id AND v.device_id=m.device_id AND $3 = ANY(v.override_endpoints)
    AND v.version=(SELECT max(x.version) FROM agent_mcp_tool_policy_versions x WHERE x.org_id=m.org_id AND x.device_id=m.device_id))`, orgID, groupID, endpoint).Scan(&out.OverridingAgents); err != nil {
		return GroupPolicy{}, err
	}
	return out, nil
}

// RemoveOverride writes the next version of an agent's own policy without its rules for endpoint and
// without that endpoint among the ones it decides for. From then on the group's policy decides for that
// server.
func (s *Service) RemoveOverride(ctx context.Context, orgID, deviceID, actorID uuid.UUID, endpoint string) (Policy, error) {
	endpoint = strings.TrimSpace(endpoint)
	if s == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil || actorID == uuid.Nil || endpoint == "" || len(endpoint) > 2048 {
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
	if current.Version == 0 || !containsEndpoint(current.OverrideEndpoints, endpoint) {
		return Policy{}, ErrOverrideNotFound
	}
	rules := make([]Rule, 0, len(current.Rules))
	removed := 0
	for _, rule := range current.Rules {
		if rule.Endpoint == endpoint {
			removed++
			continue
		}
		rules = append(rules, rule)
	}
	overrides := make([]string, 0, len(current.OverrideEndpoints))
	for _, item := range current.OverrideEndpoints {
		if item != endpoint {
			overrides = append(overrides, item)
		}
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return Policy{}, err
	}
	version := current.Version + 1
	now := time.Now().UTC()
	var created time.Time
	if err := tx.QueryRow(ctx, `INSERT INTO agent_mcp_tool_policy_versions (org_id, device_id, version, rules, inventory_observed_at, created_by_user_id, override_endpoints) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
		orgID, deviceID, version, raw, now, actorID, overrides).Scan(&created); err != nil {
		return Policy{}, err
	}
	metadata, _ := json.Marshal(map[string]any{"endpoint": endpoint, "version": version, "removed_rule_count": removed})
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_user_id, action, target_type, target_id, metadata) VALUES ($1,$2,'agent.mcp_tool_policy.override_removed','agent',$3,$4)`, orgID, actorID, deviceID.String(), metadata); err != nil {
		return Policy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Policy{}, err
	}
	return Policy{Version: version, Rules: rules, InventoryObservedAt: now, CreatedAt: created, OverrideEndpoints: overrides}, nil
}
