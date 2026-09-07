package aigateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func engineFixtureKey() map[string]any {
	return map[string]any{
		"id": "agent-key", "name": "tunnex-ai-agent", "value": "sk-bf-internal-fixture", "is_active": true, "mcp_configs": []any{},
		"provider_configs": []any{map[string]any{"id": 7, "provider": "openrouter", "allowed_models": []string{"openai/gpt-4o-mini"}, "blacklisted_models": []string{}, "allow_all_keys": false, "keys": []any{map[string]string{"key_id": "configured-provider-key"}}}},
	}
}
func newEngineFixture(t *testing.T, handler http.HandlerFunc) (*Engine, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "fixture-admin" || password != "fixture-password" {
			t.Error("missing private admin authentication")
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	engine, err := NewEngine(server.URL, "fixture-admin", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	return engine, server
}
func writeEngineJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func ensureEngineFixture(ctx context.Context, e *Engine) (EngineKey, error) {
	return e.EnsureKey(ctx, "tunnex-ai-agent", "openrouter", []string{"openai/gpt-4o-mini"}, []string{"configured-provider-key"})
}

func TestEngineURLBoundary(t *testing.T) {
	for _, base := range []string{"http://localhost:8000", "http://example.com", "https://user:password@example.com", "https://example.com/prefix", "https://example.com?query=1", "https://example.com/#fragment", "ftp://127.0.0.1"} {
		if _, err := NewEngine(base, "admin", "private"); err == nil {
			t.Errorf("accepted %s", base)
		}
	}
	for _, base := range []string{"http://127.0.0.1:8000", "http://[::1]:8000", "http://bifrost:8080", "https://private.example.com"} {
		e, err := NewEngine(base, "admin", "private")
		if err != nil {
			t.Fatal(err)
		}
		if e.client.Transport.(*http.Transport).Proxy != nil {
			t.Fatal("environment proxy enabled")
		}
	}
}
func TestEngineEnsureUpdatesStableKeyAndVerifiesBothStores(t *testing.T) {
	key := engineFixtureKey()
	key["provider_configs"].([]any)[0].(map[string]any)["allowed_models"] = []string{"old-model"}
	var puts, persistent, memory int
	e, _ := newEngineFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/governance/virtual-keys" {
			if r.URL.Query().Get("search") != "tunnex-ai-agent" {
				t.Error("missing exact-name search")
			}
			writeEngineJSON(w, map[string]any{"virtual_keys": []any{key}, "total_count": 1})
			return
		}
		if r.Method == http.MethodPut {
			puts++
			var update map[string]any
			if json.NewDecoder(r.Body).Decode(&update) != nil {
				t.Error("invalid update")
			}
			for _, field := range []string{"budgets", "rate_limit", "reset_budget_usage", "calendar_aligned", "name", "value"} {
				if _, ok := update[field]; ok {
					t.Errorf("update rewrites %s", field)
				}
			}
			pc := update["provider_configs"].([]any)[0].(map[string]any)
			if pc["id"] != float64(7) {
				t.Error("provider config identity lost")
			}
			for _, field := range []string{"budgets", "rate_limit", "model_budgets"} {
				if _, ok := pc[field]; ok {
					t.Errorf("update rewrites provider %s", field)
				}
			}
			key = engineFixtureKey()
			writeEngineJSON(w, map[string]any{})
			return
		}
		if r.URL.Query().Get("from_memory") == "true" {
			memory++
		} else {
			persistent++
		}
		writeEngineJSON(w, map[string]any{"virtual_key": key})
	})
	got, err := ensureEngineFixture(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "agent-key" || got.Value != "sk-bf-internal-fixture" || puts != 1 || persistent != 2 || memory != 1 {
		t.Fatalf("wrong result/control counts: id=%s put=%d persistent=%d memory=%d", got.ID, puts, persistent, memory)
	}
}
func TestEngineReadbackRefusesWrongScope(t *testing.T) {
	for _, kind := range []string{"model", "wildcard", "provider-key", "secret", "name", "inactive", "mcp", "team", "provider", "missing-active"} {
		t.Run(kind, func(t *testing.T) {
			e, _ := newEngineFixture(t, func(w http.ResponseWriter, r *http.Request) {
				key := engineFixtureKey()
				if r.URL.Path == "/api/governance/virtual-keys" {
					writeEngineJSON(w, map[string]any{"virtual_keys": []any{key}, "total_count": 1})
					return
				}
				if r.URL.Query().Get("from_memory") == "true" {
					pc := key["provider_configs"].([]any)[0].(map[string]any)
					switch kind {
					case "model":
						pc["allowed_models"] = []string{"different"}
					case "wildcard":
						pc["allow_all_keys"] = true
					case "provider-key":
						pc["keys"] = []any{map[string]string{"key_id": "other-secret-scope"}}
					case "secret":
						key["value"] = "wrong-secret"
					case "name":
						key["name"] = "other-agent"
					case "inactive":
						key["is_active"] = false
					case "mcp":
						key["mcp_configs"] = []any{map[string]string{"mcp_client_name": "unexpected"}}
					case "team":
						key["team_id"] = "other-tenant-team"
					case "provider":
						pc["provider"] = "other-provider"
					case "missing-active":
						delete(key, "is_active")
					}
				}
				writeEngineJSON(w, map[string]any{"virtual_key": key})
			})
			got, err := ensureEngineFixture(context.Background(), e)
			if err == nil || got.Value != "" {
				t.Fatal("unverified secret escaped")
			}
		})
	}
}
func TestEngineCreateConflictAndTimeoutRecovery(t *testing.T) {
	for _, mode := range []string{"created", "conflict", "timeout", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			var created atomic.Bool
			var posts atomic.Int32
			e, _ := newEngineFixture(t, func(w http.ResponseWriter, r *http.Request) {
				key := engineFixtureKey()
				if r.Method == http.MethodPost {
					posts.Add(1)
					created.Store(true)
					switch mode {
					case "conflict":
						http.Error(w, "secret must not escape", 409)
					case "timeout":
						select {
						case <-r.Context().Done():
						case <-time.After(200 * time.Millisecond):
						}
					case "duplicate":
						http.Error(w, "conflict", 409)
					default:
						writeEngineJSON(w, map[string]any{"virtual_key": key})
					}
					return
				}
				if r.URL.Path == "/api/governance/virtual-keys" {
					keys := []any{}
					if created.Load() {
						keys = append(keys, key)
						if mode == "duplicate" {
							keys = append(keys, key)
						}
					}
					writeEngineJSON(w, map[string]any{"virtual_keys": keys, "total_count": len(keys)})
					return
				}
				writeEngineJSON(w, map[string]any{"virtual_key": key})
			})
			if mode == "timeout" {
				e.client.Timeout = 50 * time.Millisecond
			}
			got, err := ensureEngineFixture(context.Background(), e)
			if mode == "duplicate" {
				if err == nil || got.Value != "" {
					t.Fatal("ambiguous recovery accepted")
				}
			} else if err != nil || got.ID != "agent-key" {
				t.Fatalf("%s recovery failed: %v", mode, err)
			}
			if posts.Load() != 1 {
				t.Fatalf("uncertain create repeated %d times", posts.Load())
			}
		})
	}
}
func TestEngineDisableVerifiesMemory(t *testing.T) {
	for _, mode := range []string{"inactive", "absent", "stale"} {
		t.Run(mode, func(t *testing.T) {
			e, _ := newEngineFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut {
					writeEngineJSON(w, map[string]any{})
					return
				}
				if mode == "absent" {
					w.WriteHeader(404)
					return
				}
				key := engineFixtureKey()
				key["is_active"] = mode == "stale" && r.URL.Query().Get("from_memory") == "true"
				writeEngineJSON(w, map[string]any{"virtual_key": key})
			})
			err := e.DisableKey(context.Background(), "agent-key")
			if (err != nil) != (mode == "stale") {
				t.Fatalf("disable %s: %v", mode, err)
			}
		})
	}
}
func TestEnginePriceExactAndUnknown(t *testing.T) {
	for _, kind := range []string{"known", "free", "missing", "wrong-model", "wrong-provider", "override", "negative"} {
		t.Run(kind, func(t *testing.T) {
			e, _ := newEngineFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/models/details" || r.URL.Query().Get("provider") != "openrouter" || r.URL.Query().Get("query") != "openai/gpt-4o-mini" {
					t.Error("price query scope wrong")
				}
				row := map[string]any{"name": "openai/gpt-4o-mini", "provider": "openrouter", "input_cost_per_token": 0.1, "output_cost_per_token": 0.2}
				switch kind {
				case "free":
					row["input_cost_per_token"] = 0
					row["output_cost_per_token"] = 0
				case "missing":
					delete(row, "output_cost_per_token")
				case "wrong-model":
					row["name"] = "other"
				case "wrong-provider":
					row["provider"] = "other"
				case "override":
					row["pricing_override_ids"] = []string{"scoped"}
				case "negative":
					row["input_cost_per_token"] = -1
				}
				writeEngineJSON(w, map[string]any{"models": []any{row}})
			})
			p, err := e.Price(context.Background(), "openrouter", "openai/gpt-4o-mini")
			if err != nil {
				t.Fatal(err)
			}
			if p.Known != (kind == "known" || kind == "free") {
				t.Fatalf("price %s known=%t", kind, p.Known)
			}
		})
	}
}
func TestEngineUsageNeverDefaultsToGlobal(t *testing.T) {
	var calls int
	e, _ := newEngineFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		if q.Get("virtual_key_ids") != "key-a,key-b" || q.Get("start_time") == "" || q.Get("end_time") == "" {
			t.Error("usage escaped explicit key/time scope")
		}
		if q.Get("missing_cost_only") == "true" {
			writeEngineJSON(w, map[string]any{"total_requests": 1})
			return
		}
		writeEngineJSON(w, map[string]any{"total_requests": 3, "total_tokens": 10, "prompt_tokens": 8, "completion_tokens": 2, "total_cost": 0.25})
	})
	end := time.Now()
	for _, ids := range [][]string{nil, {}, {""}, {"*"}, {"key-a,key-b"}, {"key-a", "key-a"}} {
		if _, err := e.Usage(context.Background(), ids, end.Add(-time.Hour), end); err == nil {
			t.Fatal("invalid usage scope accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid scope reached engine")
	}
	got, err := e.Usage(context.Background(), []string{"key-a", "key-b"}, end.Add(-time.Hour), end)
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalRequests != 3 || got.UncostedRequests != 1 || got.TotalCost != 0.25 || calls != 2 {
		t.Fatalf("aggregate mismatch: %+v calls=%d", got, calls)
	}
}
func TestEngineRefusesRedirectOversizeAndLeakedErrors(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls.Add(1) }))
	defer destination.Close()
	for _, mode := range []string{"redirect", "oversize", "error", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			e, _ := newEngineFixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, destination.URL, 302)
				case "oversize":
					_, _ = w.Write([]byte(strings.Repeat("s", (1<<20)+1)))
				case "error":
					http.Error(w, "private-secret-fixture", 500)
				case "timeout":
					select {
					case <-r.Context().Done():
					case <-time.After(200 * time.Millisecond):
					}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_, err := e.Price(ctx, "openrouter", "model")
			if err == nil || strings.Contains(err.Error(), "private-secret-fixture") {
				t.Fatal("unsafe success/error")
			}
		})
	}
	if destinationCalls.Load() != 0 {
		t.Fatal("redirect forwarded admin authentication")
	}
}

// TestEngineNativeAdministration qualifies this helper against the pinned
// native admin API, using only a local synthetic provider and temporary SQLite.
func TestEngineNativeAdministration(t *testing.T) {
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
		t.Fatal("binary pin mismatch")
	}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeEngineJSON(w, map[string]any{"data": []any{}}) }))
	defer provider.Close()
	dir := t.TempDir()
	pricing := filepath.Join(dir, "pricing.json")
	if err := os.WriteFile(pricing, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"client":       map[string]any{"enforce_auth_on_inference": true, "enable_logging": false, "disable_content_logging": true},
		"config_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}},
		"framework":    map[string]any{"pricing": map[string]any{"pricing_url": "file://" + pricing, "model_parameters_url": "file://" + pricing, "live_models_sync_interval": 0, "mcp_library_sync_interval": 0}},
		"governance":   map[string]any{"auth_config": map[string]any{"is_enabled": true, "admin_username": "fixture-admin", "admin_password": "fixture-password", "disable_auth_on_inference": false}},
		"providers":    map[string]any{"openrouter": map[string]any{"network_config": map[string]any{"base_url": provider.URL, "allow_private_network": true, "max_retries": 0}, "keys": []any{map[string]any{"id": "configured-provider-key", "name": "fixture-provider", "value": "fixture-only", "models": []string{"openai/gpt-4o-mini", "other-model"}, "weight": 1}}}},
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
	first, err := ensureEngineFixture(context.Background(), engine)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.EnsureKey(context.Background(), "tunnex-ai-agent", "openrouter", []string{"other-model"}, []string{"configured-provider-key"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.Value != second.Value {
		t.Fatal("policy update changed stable accounting identity")
	}
	if err = engine.DisableKey(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}
	t.Log("pinned native create, persistent and memory readback, stable-key update, and verified disable passed")
}

func TestEngineMultiScopeReadbackRefusesDrift(t *testing.T) {
	scopes := []EngineProviderScope{{Provider: "openrouter", Models: []string{"openai/gpt-4o-mini"}, KeyIDs: []string{"configured-provider-key"}}, {Provider: "anthropic", Models: []string{"claude-fixture"}, KeyIDs: []string{"anthropic-key"}}}
	for _, mode := range []string{"valid", "duplicate-provider", "duplicate-config-id", "changed-config-id", "foreign-provider", "swapped-keys", "extra-model", "missing-provider", "allow-all"} {
		t.Run(mode, func(t *testing.T) {
			key := engineFixtureKey()
			configs := key["provider_configs"].([]any)
			configs = append(configs, map[string]any{"id": 8, "provider": "anthropic", "allowed_models": []string{"claude-fixture"}, "keys": []any{map[string]string{"key_id": "anthropic-key"}}})
			key["provider_configs"] = configs
			e, _ := newEngineFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/governance/virtual-keys" {
					writeEngineJSON(w, map[string]any{"virtual_keys": []any{key}, "total_count": 1})
					return
				}
				if r.Method != "GET" {
					t.Error("matching persisted scopes must not mutate")
				}
				if r.URL.Query().Get("from_memory") == "true" {
					p := configs[1].(map[string]any)
					switch mode {
					case "duplicate-provider":
						p["provider"] = "openrouter"
					case "duplicate-config-id":
						p["id"] = 7
					case "changed-config-id":
						p["id"] = 88
					case "foreign-provider":
						p["provider"] = "unknown"
					case "swapped-keys":
						p["keys"] = []any{map[string]string{"key_id": "configured-provider-key"}}
					case "extra-model":
						p["allowed_models"] = []string{"claude-fixture", "other"}
					case "missing-provider":
						key["provider_configs"] = configs[:1]
					case "allow-all":
						p["allow_all_keys"] = true
					}
				}
				writeEngineJSON(w, map[string]any{"virtual_key": key})
			})
			_, err := e.EnsureScopedKey(context.Background(), "tunnex-ai-agent", scopes)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("unexpected result %v", err)
			}
		})
	}
	for _, scopes := range [][]EngineProviderScope{nil, {{Provider: "unknown", Models: []string{"model"}, KeyIDs: []string{"key"}}}, {scopes[0], scopes[0]}, {scopes[0], {Provider: "anthropic", Models: []string{"model"}, KeyIDs: scopes[0].KeyIDs}}} {
		if validEngineScopes(scopes) {
			t.Fatal("invalid desired scopes accepted")
		}
	}
}
