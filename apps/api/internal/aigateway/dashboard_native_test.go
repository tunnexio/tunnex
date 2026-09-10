package aigateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// The pinned engine records synthetic traffic. Only its stopped, dedicated
// SQLite timestamps are moved to qualify inclusive UTC midnight boundaries.
func TestEngineDashboardNative(t *testing.T) {
	binary := os.Getenv("AI0_BIFROST_BINARY")
	if binary == "" {
		t.Skip("explicit pinned native binary required")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if binarySHA256 == "" || hex.EncodeToString(sum[:]) != binarySHA256 {
		t.Fatal("native binary pin mismatch")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("Python SQLite prerequisite unavailable")
	}
	var arrivals atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			io.WriteString(w, `{"data":[]}`)
			return
		}
		arrivals.Add(1)
		var body struct {
			Model string `json:"model"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid fixture request")
			w.WriteHeader(400)
			return
		}
		if body.Model == "failed" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"message":"synthetic refusal","type":"invalid_request_error"}}`)
			return
		}
		fmt.Fprintf(w, `{"id":"dashboard","object":"chat.completion","model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":"DASHBOARD_PRIVATE_RESPONSE"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":3,"total_tokens":7}}`, body.Model)
	}))
	defer provider.Close()
	dir := t.TempDir()
	write := func(name string, v any) {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("prices.json", map[string]any{"priced": map[string]any{"provider": "openrouter", "mode": "chat", "input_cost_per_token": 1, "output_cost_per_token": 1}})
	write("parameters.json", map[string]any{})
	write("config.json", map[string]any{
		"client":       map[string]any{"enforce_auth_on_inference": true, "enable_logging": true, "disable_content_logging": true},
		"config_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}},
		"logs_store":   map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "logs.db")}},
		"framework":    map[string]any{"pricing": map[string]any{"pricing_url": "file://" + filepath.Join(dir, "prices.json"), "model_parameters_url": "file://" + filepath.Join(dir, "parameters.json"), "live_models_sync_interval": 0, "mcp_library_sync_interval": 0}},
		"governance":   map[string]any{"auth_config": map[string]any{"is_enabled": true, "admin_username": "dashboard-admin", "admin_password": "dashboard-fixture", "disable_auth_on_inference": false}},
		"providers":    map[string]any{"openrouter": map[string]any{"network_config": map[string]any{"base_url": provider.URL, "allow_private_network": true, "max_retries": 0}, "keys": []any{map[string]any{"id": "dashboard-provider", "name": "dashboard-provider", "value": "synthetic-only", "models": []string{"priced", "unknown", "failed"}, "weight": 1}}}},
	})
	base, stop := startEngine(t, binary, dir)
	defer func() { stop() }()
	engine, err := NewEngine(base, "dashboard-admin", "dashboard-fixture")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	keys := map[string]EngineKey{}
	for _, name := range []string{"selected", "outsider", "idle"} {
		k, e := engine.EnsureKey(ctx, "dashboard-"+name, "openrouter", []string{"priced", "unknown", "failed"}, []string{"dashboard-provider"})
		if e != nil {
			t.Fatal(e)
		}
		keys[name] = k
	}
	from := time.Now().UTC().Add(-time.Minute)
	client := &http.Client{Timeout: 10 * time.Second}
	for _, c := range []struct {
		key, model string
		status     int
	}{{"selected", "priced", 200}, {"selected", "unknown", 200}, {"selected", "failed", 400}, {"outsider", "priced", 200}} {
		b, _ := json.Marshal(map[string]any{"model": "openrouter/" + c.model, "messages": []any{map[string]string{"role": "user", "content": "DASHBOARD_PRIVATE_PROMPT"}}, "max_tokens": 8})
		r, _ := http.NewRequest("POST", base+"/v1/chat/completions", bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Bf-Vk", keys[c.key].Value)
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if e != nil || res.StatusCode != c.status {
			t.Fatalf("synthetic status=%d expected=%d", res.StatusCode, c.status)
		}
		if c.status == 200 && !bytes.Contains(body, []byte("DASHBOARD_PRIVATE_RESPONSE")) {
			t.Fatal("missing fixture completion")
		}
	}
	for deadline := time.Now().Add(15 * time.Second); ; {
		u, e := engine.Usage(ctx, []string{keys["selected"].ID, keys["outsider"].ID}, from, time.Now().UTC())
		if e == nil && u.TotalRequests == 4 && u.TotalTokens == 21 && u.TotalCost == 14 && u.UncostedRequests == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("native accounting not converged: %+v error=%v", u, e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if arrivals.Load() != 4 {
		t.Fatal("unexpected retry")
	}
	stop()
	midnight := time.Now().UTC().Truncate(24 * time.Hour)
	script := `import sqlite3,sys,datetime,pathlib
p=pathlib.Path(sys.argv[1]); selected=sys.argv[2]; outsider=sys.argv[3]; midnight=datetime.datetime.fromisoformat(sys.argv[4]); c=sqlite3.connect(p)
rows=c.execute('SELECT id,virtual_key_id,model FROM logs').fetchall(); assert len(rows)==4
for ident,key,model in rows:
 if key==selected: delta={'priced':-1,'unknown':0,'failed':1}[model]
 else: assert key==outsider and model=='priced'; delta=2
 stamp=(midnight+datetime.timedelta(seconds=delta)).strftime('%Y-%m-%d %H:%M:%S+00:00')
 c.execute('UPDATE logs SET timestamp=? WHERE id=?',(stamp,ident))
c.commit(); dump='\n'.join(c.iterdump()); assert 'DASHBOARD_PRIVATE_PROMPT' not in dump and 'DASHBOARD_PRIVATE_RESPONSE' not in dump
c.close()
`
	cmd := exec.Command(python, "-c", script, filepath.Join(dir, "logs.db"), keys["selected"].ID, keys["outsider"].ID, midnight.Format(time.RFC3339))
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("isolated timestamp fixture: %v %s", e, output)
	}
	base, stop = startEngine(t, binary, dir)
	engine, err = NewEngine(base, "dashboard-admin", "dashboard-fixture")
	if err != nil {
		t.Fatal(err)
	}
	start, end := midnight.Add(-time.Hour), midnight.Add(time.Hour)
	t.Run("scoped_rankings_outcomes_models_missing_cost_and_midnight", func(t *testing.T) {
		got, e := engine.Dashboard(ctx, []string{keys["selected"].ID}, start, end)
		if e != nil {
			t.Fatal(e)
		}
		if got.Usage.TotalRequests != 3 || got.Usage.TotalTokens != 14 || got.Usage.TotalCost != 7 || got.Usage.UncostedRequests != 1 {
			t.Fatalf("wrong scoped totals: %+v", got.Usage)
		}
		if got.Dashboard.SuccessfulRequests != 2 || got.Dashboard.FailedRequests != 1 || got.Dashboard.CancelledRequests != 0 {
			t.Fatalf("wrong outcomes: %+v", got.Dashboard)
		}
		if len(got.Keys) != 1 {
			t.Fatalf("out-of-scope ranking: %d keys", len(got.Keys))
		}
		k := got.Keys[keys["selected"].ID]
		if k.Requests != 3 || k.Tokens != 14 || k.Cost != 7 || k.UncostedRequests != 1 {
			t.Fatalf("wrong ranking: %+v", k)
		}
		days := got.Dashboard.Daily
		if len(days) != 2 {
			t.Fatalf("expected two UTC days: %+v", days)
		}
		if days[0].Date != start.Format("2006-01-02") || days[0].Requests != 1 || days[0].Tokens != 7 || days[0].Cost != 7 || days[0].UncostedRequests != 0 {
			t.Fatalf("wrong preceding day: %+v", days[0])
		}
		if days[1].Date != midnight.Format("2006-01-02") || days[1].Requests != 2 || days[1].Tokens != 7 || days[1].Cost != 0 || days[1].UncostedRequests != 1 {
			t.Fatalf("wrong midnight day: %+v", days[1])
		}
		costs := map[string]float64{}
		for _, m := range got.Dashboard.Models {
			costs[m.Name] = m.Cost
		}
		if costs["priced"] != 7 {
			t.Fatalf("wrong model spend: %+v", costs)
		}
	})
	t.Run("other_key_live_control", func(t *testing.T) {
		got, e := engine.Dashboard(ctx, []string{keys["outsider"].ID}, start, end)
		if e != nil {
			t.Fatal(e)
		}
		if got.Usage.TotalRequests != 1 || got.Usage.TotalTokens != 7 || got.Usage.TotalCost != 7 || len(got.Keys) != 1 || got.Keys[keys["outsider"].ID].Requests != 1 {
			t.Fatalf("control not isolated: %+v", got)
		}
	})
	t.Run("idle_key_real_empty_shapes", func(t *testing.T) {
		got, e := engine.Dashboard(ctx, []string{keys["idle"].ID}, start, end)
		if e != nil {
			t.Fatal(e)
		}
		if got.Usage.TotalRequests != 0 || got.Usage.TotalTokens != 0 || got.Usage.TotalCost != 0 || len(got.Keys) != 0 {
			t.Fatalf("empty scope leaked data: %+v", got)
		}
		for _, d := range got.Dashboard.Daily {
			if d.Requests != 0 || d.Tokens != 0 || d.Cost != 0 || d.UncostedRequests != 0 {
				t.Fatalf("nonzero empty day: %+v", d)
			}
		}
	})
	t.Run("supported_native_bucket_widths_preserve_scoped_totals", func(t *testing.T) {
		for _, width := range []time.Duration{24 * time.Hour, 3 * 24 * time.Hour, 7 * 24 * time.Hour, 31 * 24 * time.Hour} {
			t.Run(width.String(), func(t *testing.T) {
				got, e := engine.Dashboard(ctx, []string{keys["selected"].ID}, end.Add(-width), end)
				if e != nil {
					t.Fatal(e)
				}
				var requests, tokens, missing int64
				var cost float64
				for _, day := range got.Dashboard.Daily {
					requests += day.Requests
					tokens += day.Tokens
					missing += day.UncostedRequests
					cost += day.Cost
				}
				if requests != 3 || tokens != 14 || missing != 1 || cost != 7 {
					t.Fatalf("native bucket folding lost/duplicated records: requests=%d tokens=%d missing=%d cost=%g", requests, tokens, missing, cost)
				}
			})
		}
	})
	t.Run("native_midnight_end_is_inclusive", func(t *testing.T) {
		got, e := engine.Dashboard(ctx, []string{keys["selected"].ID}, midnight.Add(-time.Second), midnight)
		if e != nil {
			t.Fatal(e)
		}
		if got.Usage.TotalRequests != 2 || got.Usage.TotalTokens != 14 || got.Usage.TotalCost != 7 {
			t.Fatalf("wrong inclusive midnight: %+v", got.Usage)
		}
	})
}
