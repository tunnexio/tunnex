// Package mcptoolpolicy owns immutable F14 allow policies for explicit MCP proxies.
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
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound       = errors.New("MCP tool policy not found")
	ErrInvalid        = errors.New("invalid MCP tool policy")
	ErrUnobservedTool = errors.New("MCP tool policy contains an unobserved tool")
)

type Rule struct {
	Endpoint        string `json:"endpoint"`
	ServerName      string `json:"server_name"`
	ToolName        string `json:"tool_name"`
	InputSchemaHash string `json:"input_schema_hash"`
}

type Policy struct {
	Version             int64
	Rules               []Rule
	InventoryObservedAt time.Time
	CreatedAt           time.Time
}

type Service struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func (s *Service) Get(ctx context.Context, orgID, deviceID uuid.UUID) (Policy, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil {
		return Policy{}, ErrInvalid
	}
	var p Policy
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT version, rules, inventory_observed_at, created_at
FROM agent_mcp_tool_policy_versions WHERE org_id=$1 AND device_id=$2 ORDER BY version DESC LIMIT 1`, orgID, deviceID).
		Scan(&p.Version, &raw, &p.InventoryObservedAt, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil || json.Unmarshal(raw, &p.Rules) != nil {
		return Policy{}, ErrInvalid
	}
	return p, nil
}

// Runtime returns only rules which still match the most recently observed
// inventory. Inventory older than one minute, a missing policy, or a changed
// tool produces the same empty allow-list. This makes the proxy default-deny
// without teaching it database details or allowing an old schema hash through.
func (s *Service) Runtime(ctx context.Context, orgID, deviceID uuid.UUID, now time.Time) (Policy, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil {
		return Policy{}, ErrInvalid
	}
	var snapshot []byte
	var observed time.Time
	err := s.pool.QueryRow(ctx, `SELECT i.snapshot, i.observed_at FROM agent_mcp_inventory i
JOIN devices d ON d.id=i.device_id
WHERE d.id=$1 AND d.org_id=$2 AND d.kind='agent' AND d.deleted_at IS NULL`, deviceID, orgID).Scan(&snapshot, &observed)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{Version: 0}, nil
	}
	if err != nil {
		return Policy{}, err
	}
	if now.UTC().Sub(observed) > time.Minute || observed.After(now.UTC().Add(time.Minute)) {
		return Policy{Version: 0, InventoryObservedAt: observed}, nil
	}
	p, err := s.Get(ctx, orgID, deviceID)
	if errors.Is(err, ErrNotFound) {
		return Policy{Version: 0, InventoryObservedAt: observed}, nil
	}
	if err != nil {
		return Policy{}, err
	}
	available := inventoryRules(snapshot)
	allowed := make([]Rule, 0, len(p.Rules))
	for _, rule := range p.Rules {
		if available[ruleKey(rule)] {
			allowed = append(allowed, rule)
		}
	}
	p.Rules, p.InventoryObservedAt = allowed, observed
	return p, nil
}

// Replace validates every requested rule against the agent's last secret-free inventory,
// writes a new immutable version, and appends one audit event in the same transaction.
func (s *Service) Replace(ctx context.Context, orgID, deviceID, actorID uuid.UUID, rules []Rule) (Policy, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil || actorID == uuid.Nil {
		return Policy{}, ErrInvalid
	}
	rules = canonicalRules(rules)
	if rules == nil {
		return Policy{}, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Policy{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Serialize version allocation per agent. The inventory itself is read after
	// this lock, so a concurrent policy replacement cannot reuse a version.
	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM devices WHERE id=$1 AND org_id=$2 AND kind='agent' AND deleted_at IS NULL FOR UPDATE`, deviceID, orgID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Policy{}, ErrNotFound
		}
		return Policy{}, err
	}
	var snapshot []byte
	var observed time.Time
	err = tx.QueryRow(ctx, `SELECT i.snapshot, i.observed_at FROM agent_mcp_inventory i
JOIN devices d ON d.id=i.device_id
WHERE d.id=$1 AND d.org_id=$2 AND d.kind='agent' AND d.deleted_at IS NULL FOR SHARE`, deviceID, orgID).Scan(&snapshot, &observed)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, err
	}
	available := inventoryRules(snapshot)
	for _, rule := range rules {
		if !available[ruleKey(rule)] {
			return Policy{}, ErrUnobservedTool
		}
	}
	var version int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0)+1 FROM agent_mcp_tool_policy_versions WHERE device_id=$1`, deviceID).Scan(&version); err != nil {
		return Policy{}, err
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return Policy{}, err
	}
	var created time.Time
	err = tx.QueryRow(ctx, `INSERT INTO agent_mcp_tool_policy_versions (org_id, device_id, version, rules, inventory_observed_at, created_by_user_id)
VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at`, orgID, deviceID, version, raw, observed, actorID).Scan(&created)
	if err != nil {
		return Policy{}, err
	}
	metadata, _ := json.Marshal(map[string]any{"version": version, "rule_count": len(rules), "inventory_observed_at": observed.UTC().Format(time.RFC3339Nano)})
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_user_id, action, target_type, target_id, metadata) VALUES ($1,$2,'agent.mcp_tool_policy.replaced','agent',$3,$4)`, orgID, actorID, deviceID.String(), metadata); err != nil {
		return Policy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Policy{}, err
	}
	return Policy{Version: version, Rules: rules, InventoryObservedAt: observed, CreatedAt: created}, nil
}

func canonicalRules(in []Rule) []Rule {
	if len(in) > 1024 {
		return nil
	}
	out := make([]Rule, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, rule := range in {
		rule.Endpoint, rule.ServerName, rule.ToolName, rule.InputSchemaHash = strings.TrimSpace(rule.Endpoint), strings.TrimSpace(rule.ServerName), strings.TrimSpace(rule.ToolName), strings.TrimSpace(rule.InputSchemaHash)
		if rule.Endpoint == "" || rule.ServerName == "" || rule.ToolName == "" || rule.InputSchemaHash == "" || len(rule.Endpoint) > 2048 || len(rule.ServerName) > 512 || len(rule.ToolName) > 512 || len(rule.InputSchemaHash) > 128 {
			return nil
		}
		key := ruleKey(rule)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return ruleKey(out[i]) < ruleKey(out[j]) })
	return out
}

func ruleKey(rule Rule) string {
	return rule.Endpoint + "\x00" + rule.ServerName + "\x00" + rule.ToolName + "\x00" + rule.InputSchemaHash
}

func inventoryRules(snapshot []byte) map[string]bool {
	var value struct {
		Servers []struct {
			Endpoint   string `json:"endpoint"`
			ServerName string `json:"server_name"`
			Tools      []struct {
				Name            string `json:"name"`
				InputSchemaHash string `json:"input_schema_hash"`
			} `json:"tools"`
		} `json:"servers"`
	}
	out := map[string]bool{}
	if json.Unmarshal(snapshot, &value) != nil {
		return out
	}
	for _, server := range value.Servers {
		for _, tool := range server.Tools {
			out[ruleKey(Rule{Endpoint: server.Endpoint, ServerName: server.ServerName, ToolName: tool.Name, InputSchemaHash: tool.InputSchemaHash})] = true
		}
	}
	return out
}
