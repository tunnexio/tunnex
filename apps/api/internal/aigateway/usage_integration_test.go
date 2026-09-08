package aigateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestAIUsagePostgresHistoricalTeamAndTenantScope(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newAICredentialFixture(t, ctx, pool)
	other := newAICredentialFixture(t, ctx, pool)
	empty := newAICredentialFixture(t, ctx, pool)
	oldTeam, newTeam, foreignTeam := uuid.New(), uuid.New(), uuid.New()
	for _, row := range []struct{ org, team uuid.UUID }{{f.org, oldTeam}, {f.org, newTeam}, {other.org, foreignTeam}} {
		f.exec(`INSERT INTO agent_groups(id,org_id,name) VALUES($1,$2,$3)`, row.team, row.org, "team-"+row.team.String())
		f.exec(`INSERT INTO ai_gateway_team_policies(org_id,team_id,models,key_ids,revision) VALUES($1,$2,'{openrouter/model}','{provider-key}',1)`, row.org, row.team)
	}
	for _, row := range []struct {
		org, device, team uuid.UUID
		key               string
	}{{f.org, f.device, oldTeam, "historic-team-key"}, {f.org, f.device, newTeam, "current-team-key"}, {other.org, other.device, foreignTeam, "other-tenant-key"}} {
		f.exec(`INSERT INTO ai_gateway_key_bindings(org_id,device_id,team_id,native_key_id,sealed_key,binding_revision) VALUES($1,$2,$3,$4,'fixture-sealed-only',1)`, row.org, row.device, row.team, row.key)
	}
	f.exec(`INSERT INTO ai_gateway_assignments(org_id,device_id,team_id,enabled,revision,status) VALUES($1,$2,$3,true,1,'pending')`, f.org, f.device, newTeam)
	// Old membership can disappear and the group can be archived; past native
	// requests still belong to the original binding's team.
	f.exec(`UPDATE agent_groups SET archived_at=now() WHERE id=$1`, oldTeam)
	calls := 0
	var selected []string
	engine := usageEngineFixture{usage: func(_ context.Context, ids []string, from, to time.Time) (Usage, error) {
		calls++
		selected = append([]string{}, ids...)
		return Usage{TotalRequests: int64(len(ids)), TotalCost: float64(len(ids))}, nil
	}}
	service := &Policies{pool: pool, engine: engine}
	for _, tc := range []struct {
		name         string
		team, device *uuid.UUID
		ids          []string
	}{
		{"org", nil, nil, []string{"current-team-key", "historic-team-key"}},
		{"old team after move", &oldTeam, nil, []string{"historic-team-key"}},
		{"current team", &newTeam, nil, []string{"current-team-key"}},
		{"agent all history", nil, &f.device, []string{"current-team-key", "historic-team-key"}},
		{"agent historical team", &oldTeam, &f.device, []string{"historic-team-key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := service.Usage(ctx, f.org, tc.team, tc.device, time.Time{}, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			sort.Strings(selected)
			if !reflect.DeepEqual(selected, tc.ids) || got.TotalRequests != int64(len(tc.ids)) {
				t.Fatalf("wrong scoped native keys: %v expected %v", selected, tc.ids)
			}
		})
	}
	before := calls
	for _, scope := range []struct{ team, device *uuid.UUID }{{&foreignTeam, nil}, {nil, &other.device}, {&foreignTeam, &other.device}} {
		if _, err := service.Usage(ctx, f.org, scope.team, scope.device, time.Time{}, time.Time{}); usageStatus(err) != 404 {
			t.Fatalf("cross-tenant filter error=%v", err)
		}
	}
	if calls != before {
		t.Fatal("cross-tenant selector reached native ledger")
	}
	zero, err := service.Usage(ctx, empty.org, nil, nil, time.Time{}, time.Time{})
	if err != nil || zero != (Usage{}) || calls != before {
		t.Fatalf("empty org did not return explicit zero without native query: %+v %v", zero, err)
	}
	// Monetary checks use exactly the caller-owned transaction. A one-slot pool
	// makes any accidental second acquisition block until the deadline.
	cfg := pool.Config()
	cfg.MaxConns = 1
	single, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer single.Close()
	one := 1.0
	monetary := &Policies{pool: single, engine: usageEngineFixture{
		price: func(context.Context, string, string) (Price, error) { return Price{true, &one, &one}, nil },
		usage: func(_ context.Context, ids []string, from, to time.Time) (Usage, error) {
			if !reflect.DeepEqual(ids, []string{"current-team-key"}) {
				t.Errorf("monetary team IDs wrong: %v", ids)
			}
			return Usage{}, nil
		},
	}}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	tx, err := single.Begin(bounded)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := monetary.enforceCost(bounded, tx, f.org, newTeam, "openrouter/model", &one); err != nil {
		t.Fatal(err)
	}
	var witness int
	if err := tx.QueryRow(bounded, `SELECT 1`).Scan(&witness); err != nil || witness != 1 {
		t.Fatalf("cost helper ended caller transaction: %v", err)
	}
	if err := tx.Rollback(bounded); err != nil {
		t.Fatal(err)
	}
	t.Log("scoped native IDs preserve historical team attribution; foreign tenant and zero-binding calls never query engine; monetary read uses caller transaction with one-slot pool")
}

// TestAIUsageNativeLedgerAndCostAdmission connects retained CP attribution to
// the real pinned native metadata ledger. The provider is a zero-spend fixture.
func TestAIUsageNativeLedgerAndCostAdmission(t *testing.T) {
	binary := os.Getenv("AI0_BIFROST_BINARY")
	if binary == "" {
		t.Skip("set AI0_BIFROST_BINARY to pinned native fixture")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("pinned binary unavailable")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != binarySHA256 {
		t.Fatal("binary digest mismatch")
	}
	ctx, pool := testpostgres.New(t)
	f := newAICredentialFixture(t, ctx, pool)
	team := uuid.New()
	f.exec(`INSERT INTO agent_groups(id,org_id,name) VALUES($1,$2,'native-usage-team')`, team, f.org)
	f.exec(`INSERT INTO ai_gateway_team_policies(org_id,team_id,models,key_ids,revision) VALUES($1,$2,'{openrouter/costed}','{fixture-provider}',1)`, f.org, team)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"data":[]}`)
			return
		}
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, `{"id":"native-cost-fixture","object":"chat.completion","model":"costed","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":3,"total_tokens":7}}`)
	}))
	defer provider.Close()
	dir := t.TempDir()
	pricing := filepath.Join(dir, "pricing.json")
	if err = os.WriteFile(pricing, []byte(`{"costed":{"provider":"openrouter","mode":"chat","input_cost_per_token":1,"output_cost_per_token":1}}`), 0600); err != nil {
		t.Fatal(err)
	}
	params := filepath.Join(dir, "parameters.json")
	if err = os.WriteFile(params, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"client":       map[string]any{"enforce_auth_on_inference": true, "enable_logging": true, "disable_content_logging": true, "log_retention_days": 7},
		"config_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}},
		"logs_store":   map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "logs.db")}, "retention_days": 7},
		"framework":    map[string]any{"pricing": map[string]any{"pricing_url": "file://" + pricing, "model_parameters_url": "file://" + params, "live_models_sync_interval": 0, "mcp_library_sync_interval": 0}},
		"governance":   map[string]any{"auth_config": map[string]any{"is_enabled": true, "admin_username": "fixture-admin", "admin_password": "fixture-password", "disable_auth_on_inference": false}},
		"providers":    map[string]any{"openrouter": map[string]any{"network_config": map[string]any{"base_url": provider.URL, "allow_private_network": true, "max_retries": 0}, "keys": []any{map[string]any{"id": "fixture-provider", "name": "fixture-provider", "value": "fixture-only", "models": []string{"costed"}, "weight": 1}}}},
	}
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "config.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	base, stop := startEngine(t, binary, dir)
	defer stop()
	engine, err := NewEngine(base, "fixture-admin", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	key, err := engine.EnsureKey(ctx, "native-usage-agent", "openrouter", []string{"costed"}, []string{"fixture-provider"})
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO ai_gateway_key_bindings(org_id,device_id,team_id,native_key_id,sealed_key,binding_revision) VALUES($1,$2,$3,$4,'fixture-sealed',1)`, f.org, f.device, team, key.ID)
	service := &Policies{pool: pool, engine: engine}
	limit := 7.0
	check := func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(context.Background())
		return service.enforceCost(ctx, tx, f.org, team, "openrouter/costed", &limit)
	}
	if err := check(); err != nil {
		t.Fatalf("native priced empty observation refused: %v", err)
	}
	request, _ := http.NewRequestWithContext(ctx, "POST", base+"/v1/chat/completions", strings.NewReader(`{"model":"openrouter/costed","messages":[{"role":"user","content":"OK"}],"max_tokens":8}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Bf-Vk", key.Value)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("native fixture status=%d", response.StatusCode)
	}
	var observed Usage
	for end := time.Now().Add(12 * time.Second); ; {
		observed, err = service.Usage(ctx, f.org, &team, &f.device, time.Time{}, time.Time{})
		if err == nil && observed.TotalRequests == 1 && observed.TotalTokens == 7 && observed.TotalCost == 7 && observed.UncostedRequests == 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("native scoped observation did not converge: %+v err=%v", observed, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	requireDailyThreshold(t, check())
	t.Log("real pinned exact pricing plus CP-selected native metadata: one request/seven tokens/seven synthetic cost units; below-threshold admission passed and post-accounting threshold denied")
}
